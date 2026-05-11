"""Lightweight web dashboard for audit/session/report visibility."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import secrets
import threading
import hashlib
import hmac
import html
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from tools.audit_logger import write_audit_event
from tools.playbooks import (
    clone_playbook,
    create_or_update_playbook,
    delete_playbook,
    ensure_playbook_store,
    get_playbook,
    list_playbook_runs,
    list_playbooks,
    run_playbook_runtime,
    validate_playbook_yaml,
)
from tools.time_utils import configured_timezone, now_tz, to_configured_tz
from tools.subscription import (
    get_subscription_status,
    invalidate_subscription_cache,
    subscription_license_path,
)

_STARTED = False
_LOCK = threading.Lock()
_MCP_INSTANCE = None

_DEFAULT_AUDIT_PATH = "/opt/uts-mcp/logs/mcp_audit.jsonl"
_DEFAULT_REPORTS_DIR = "/opt/uts-mcp/reports"
_DEFAULT_OUTPUT_DIR = "/opt/uts-mcp/output"
_DEFAULT_CHAT_HISTORY_DIR = "/opt/uts-mcp/logs/chat_sessions"
_MAX_SUBSCRIPTION_UPLOAD_BYTES = 128 * 1024
_SESSION_COOKIE_NAME = "uts_dash_session"
_SESSION_TTL_SECONDS = 12 * 60 * 60
_SESSION_STORE: dict[str, datetime] = {}
_AUTH_LOCK = threading.Lock()
_LOGIN_ATTEMPTS: dict[str, list[datetime]] = {}
_LOGIN_LOCKOUT: dict[str, datetime] = {}
_SYSTEM_EVENT_TYPES = {"server.start", "dashboard.listen", "dashboard.start"}


def _build_tool_registry() -> dict:
    registry: dict[str, object] = {}
    if _MCP_INSTANCE is None:
        return registry
    tool_manager = getattr(_MCP_INSTANCE, "_tool_manager", None)
    if tool_manager is None:
        return registry
    for item in getattr(tool_manager, "_tools", {}).values():
        name = getattr(item, "name", "")
        fn = getattr(item, "fn", None)
        if name and fn:
            registry[str(name)] = fn
    return registry


def _dashboard_auth_token() -> str:
    return os.environ.get("MCP_DASHBOARD_AUTH_TOKEN", "").strip()


def _dashboard_username() -> str:
    return os.environ.get("MCP_DASHBOARD_USERNAME", "").strip()


def _dashboard_password() -> str:
    return os.environ.get("MCP_DASHBOARD_PASSWORD", "").strip()


def _dashboard_password_hash() -> str:
    return os.environ.get("MCP_DASHBOARD_PASSWORD_HASH", "").strip()


def _login_max_attempts() -> int:
    raw = os.environ.get("MCP_DASHBOARD_LOGIN_MAX_ATTEMPTS", "5").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 5


def _login_window_seconds() -> int:
    raw = os.environ.get("MCP_DASHBOARD_LOGIN_WINDOW_SECONDS", "300").strip()
    try:
        return max(30, int(raw))
    except ValueError:
        return 300


def _login_lockout_seconds() -> int:
    raw = os.environ.get("MCP_DASHBOARD_LOGIN_LOCKOUT_SECONDS", "900").strip()
    try:
        return max(30, int(raw))
    except ValueError:
        return 900


def _cookie_secure_enabled() -> bool:
    raw = os.environ.get("MCP_DASHBOARD_COOKIE_SECURE", "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _token_auth_enabled() -> bool:
    return bool(_dashboard_auth_token())


def _login_auth_enabled() -> bool:
    return bool(_dashboard_username() and (_dashboard_password() or _dashboard_password_hash()))


def _extract_bearer_token(auth_header: str) -> str:
    value = str(auth_header or "").strip()
    if not value.lower().startswith("bearer "):
        return ""
    return value[7:].strip()


def _parse_cookie_header(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    raw = str(cookie_header or "").strip()
    if not raw:
        return cookies
    for chunk in raw.split(";"):
        part = chunk.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        cookies[key.strip()] = value.strip()
    return cookies


def _session_is_valid(session_id: str) -> bool:
    with _AUTH_LOCK:
        expiry = _SESSION_STORE.get(session_id)
        if not expiry:
            return False
        if now_tz() > expiry:
            _SESSION_STORE.pop(session_id, None)
            return False
        return True


def _issue_session() -> tuple[str, datetime]:
    sid = secrets.token_urlsafe(32)
    expiry = now_tz() + timedelta(seconds=_SESSION_TTL_SECONDS)
    with _AUTH_LOCK:
        _SESSION_STORE[sid] = expiry
    return sid, expiry


def _clear_session(session_id: str) -> None:
    with _AUTH_LOCK:
        _SESSION_STORE.pop(session_id, None)


def _authorized_via_login_cookie(headers) -> bool:
    if not _login_auth_enabled():
        return False
    cookies = _parse_cookie_header(headers.get("Cookie", ""))
    sid = cookies.get(_SESSION_COOKIE_NAME, "")
    return _session_is_valid(sid)


def _verify_password(candidate_password: str) -> bool:
    candidate = str(candidate_password or "")
    hash_spec = _dashboard_password_hash()
    if hash_spec:
        # Format: pbkdf2_sha256$<iterations>$<salt>$<hex_digest>
        parts = hash_spec.split("$")
        if len(parts) != 4:
            return False
        algo, raw_iter, salt, expected_hex = parts
        if algo != "pbkdf2_sha256":
            return False
        try:
            iterations = int(raw_iter)
        except ValueError:
            return False
        if iterations < 10_000:
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            candidate.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()
        return hmac.compare_digest(derived, expected_hex)

    configured = _dashboard_password()
    if not configured:
        return False
    return hmac.compare_digest(candidate, configured)


def _client_ip(headers, client_address) -> str:
    xff = str(headers.get("X-Forwarded-For", "")).strip()
    if xff:
        # Use left-most original client IP.
        return xff.split(",")[0].strip()
    if client_address and client_address[0]:
        return str(client_address[0])
    return "unknown"


def _purge_auth_state(now: datetime) -> None:
    lockout_cutoff_keys = [ip for ip, until in _LOGIN_LOCKOUT.items() if now >= until]
    for ip in lockout_cutoff_keys:
        _LOGIN_LOCKOUT.pop(ip, None)

    window = timedelta(seconds=_login_window_seconds())
    for ip, attempts in list(_LOGIN_ATTEMPTS.items()):
        fresh = [ts for ts in attempts if now - ts <= window]
        if fresh:
            _LOGIN_ATTEMPTS[ip] = fresh
        else:
            _LOGIN_ATTEMPTS.pop(ip, None)


def _is_login_locked(client_ip: str) -> tuple[bool, int]:
    now = now_tz()
    with _AUTH_LOCK:
        _purge_auth_state(now)
        until = _LOGIN_LOCKOUT.get(client_ip)
        if not until:
            return False, 0
        remaining = int((until - now).total_seconds())
        return remaining > 0, max(0, remaining)


def _record_login_failure(client_ip: str) -> tuple[bool, int]:
    now = now_tz()
    with _AUTH_LOCK:
        _purge_auth_state(now)
        attempts = _LOGIN_ATTEMPTS.setdefault(client_ip, [])
        attempts.append(now)
        max_attempts = _login_max_attempts()
        if len(attempts) >= max_attempts:
            lockout_seconds = _login_lockout_seconds()
            until = now + timedelta(seconds=lockout_seconds)
            _LOGIN_LOCKOUT[client_ip] = until
            _LOGIN_ATTEMPTS[client_ip] = []
            return True, lockout_seconds
        return False, 0


def _clear_login_failures(client_ip: str) -> None:
    with _AUTH_LOCK:
        _LOGIN_ATTEMPTS.pop(client_ip, None)
        _LOGIN_LOCKOUT.pop(client_ip, None)


def _is_authorized(headers, query: dict[str, list[str]]) -> bool:
    # If no auth mode configured, allow.
    if not _token_auth_enabled() and not _login_auth_enabled():
        return True

    if _token_auth_enabled():
        expected = _dashboard_auth_token()
        candidate = _extract_bearer_token(headers.get("Authorization", ""))
        if not candidate:
            candidate = str((query.get("token") or [""])[0]).strip()
        if candidate == expected:
            return True

    if _login_auth_enabled() and _authorized_via_login_cookie(headers):
        return True

    return False


def _iso_to_dt(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(configured_timezone())


def _to_iso(value: datetime) -> str:
    return to_configured_tz(value).isoformat()


def _normalize_timestamp_text(value: str) -> str:
    dt = _iso_to_dt(str(value or ""))
    if dt is None:
        return str(value or "")
    return _to_iso(dt)


def _normalize_event_for_display(event: dict) -> dict:
    row = dict(event or {})
    row["timestamp"] = _normalize_timestamp_text(str(row.get("timestamp", "")))
    return row


def _event_session_id(event: dict) -> str:
    payload = event.get("payload", {})
    payload = payload if isinstance(payload, dict) else {}
    return str(
        payload.get("event_session_id")
        or payload.get("mcp_session_id")
        or payload.get("session_id")
        or payload.get("main_session_id")
        or ""
    ).strip()


def _event_invocation_id(event: dict) -> str:
    payload = event.get("payload", {})
    payload = payload if isinstance(payload, dict) else {}
    return str(payload.get("invocation_id", "")).strip()


def _build_session_flow_groups(events: list[dict]) -> dict:
    grouped: dict[str, list[dict]] = {}
    ordered_keys: list[str] = []
    invalid_rows: list[dict] = []

    for event in events:
        sid = _event_session_id(event)
        if not sid:
            continue
        event_type = str(event.get("event_type", "")).strip()
        inv_id = _event_invocation_id(event)
        if not inv_id:
            if not event_type.startswith("tool.") and not event_type.startswith("command."):
                continue
            invalid_rows.append(
                {
                    "session_id": sid,
                    "reason": "missing invocation_id",
                    "event_types": [event_type],
                    "event_count": 1,
                    "events": [_normalize_event_for_display(event)],
                }
            )
            continue
        key = f"{sid}::{inv_id}"
        if key not in grouped:
            grouped[key] = []
            ordered_keys.append(key)
        grouped[key].append(event)

    valid: list[dict] = []
    for key in ordered_keys:
        rows = grouped.get(key, [])
        if not rows:
            continue
        sid, _, inv_id = key.partition("::")
        rows = sorted(rows, key=lambda row: str(row.get("timestamp", "")))
        event_types = [str(row.get("event_type", "")).strip() for row in rows if str(row.get("event_type", "")).strip()]
        warnings: list[str] = []
        if "tool.invoke" not in event_types:
            warnings.append("missing tool.invoke")
        if not {"tool.result", "tool.error", "tool.cancelled"}.intersection(set(event_types)):
            warnings.append("missing terminal tool event")
        payload0 = rows[0].get("payload", {})
        payload0 = payload0 if isinstance(payload0, dict) else {}
        tool_name = str(payload0.get("tool", "")).strip()
        valid.append(
            {
                "session_id": sid,
                "invocation_id": inv_id,
                "tool": tool_name,
                "warnings": warnings,
                "start": _normalize_timestamp_text(str(rows[0].get("timestamp", ""))),
                "end": _normalize_timestamp_text(str(rows[-1].get("timestamp", ""))),
                "steps": [_normalize_event_for_display(e) for e in rows],
            }
        )

    return {"valid": valid, "invalid": invalid_rows}


def _normalize_chat_turn_for_display(turn: dict) -> dict:
    row = dict(turn or {})
    row["timestamp"] = _normalize_timestamp_text(str(row.get("timestamp", "")))
    row["report_paths"] = _normalize_existing_report_paths(_coerce_string_list(row.get("report_paths", [])))
    return row


def _audit_log_path() -> Path:
    path = os.environ.get("MCP_AUDIT_LOG_PATH", _DEFAULT_AUDIT_PATH).strip()
    return Path(path or _DEFAULT_AUDIT_PATH)


def _reports_dir() -> Path:
    path = os.environ.get("MCP_REPORTS_DIR", _DEFAULT_REPORTS_DIR).strip()
    return Path(path or _DEFAULT_REPORTS_DIR)


def _output_dir() -> Path:
    path = os.environ.get("MCP_OUTPUT_DIR", _DEFAULT_OUTPUT_DIR).strip()
    return Path(path or _DEFAULT_OUTPUT_DIR)


def _chat_history_dir() -> Path:
    path = os.environ.get("MCP_CHAT_HISTORY_DIR", _DEFAULT_CHAT_HISTORY_DIR).strip()
    return Path(path or _DEFAULT_CHAT_HISTORY_DIR)


def _dashboard_assets_dir() -> Path:
    return Path(__file__).resolve().parent / "dashboard_assets"


def _dashboard_asset_path(asset_name: str) -> Path:
    safe_name = Path(str(asset_name or "")).name
    if not safe_name:
        raise ValueError("Invalid asset name")
    path = (_dashboard_assets_dir() / safe_name).resolve()
    try:
        path.relative_to(_dashboard_assets_dir().resolve())
    except Exception as exc:
        raise ValueError("Invalid asset path") from exc
    return path


def _read_dashboard_asset(asset_name: str) -> str:
    try:
        path = _dashboard_asset_path(asset_name)
    except Exception:
        return ""
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _required_dashboard_assets() -> list[str]:
    return ["index.html", "dashboard.css", "dashboard.js"]


def _validate_dashboard_assets_or_raise() -> None:
    missing: list[str] = []
    for asset_name in _required_dashboard_assets():
        try:
            path = _dashboard_asset_path(asset_name)
        except Exception:
            missing.append(asset_name)
            continue
        if not path.exists() or not path.is_file():
            missing.append(asset_name)
    if missing:
        payload = {
            "success": False,
            "error": "Required dashboard static assets are missing",
            "missing_assets": missing,
            "assets_dir": str(_dashboard_assets_dir()),
        }
        write_audit_event("dashboard.assets.missing", payload)
        raise RuntimeError(
            "Dashboard startup aborted: missing assets: "
            + ", ".join(missing)
            + f" in {str(_dashboard_assets_dir())}"
        )


def _safe_session_key(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    cleaned = cleaned.strip("._")
    return cleaned[:128] if cleaned else ""


def _chat_session_path(session_id: str) -> Path:
    key = _safe_session_key(session_id)
    if not key:
        raise ValueError("Invalid session id")
    return _chat_history_dir() / f"{key}.jsonl"


def _coerce_string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    rows: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if text:
            rows.append(text)
    return rows


def _load_chat_turns(session_id: str, max_turns: int = 1000) -> list[dict]:
    try:
        path = _chat_session_path(session_id)
    except Exception:
        return []
    if not path.exists():
        return []

    turns: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if isinstance(row, dict):
                turns.append(row)
    if len(turns) > max_turns:
        turns = turns[-max_turns:]
    turns.sort(key=lambda t: str(t.get("timestamp", "")))
    return turns


def _list_chat_sessions() -> list[dict]:
    base = _chat_history_dir()
    if not base.exists():
        return []

    rows: list[dict] = []
    for file_path in sorted(base.glob("*.jsonl"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
        if not file_path.is_file():
            continue
        turns = _load_chat_turns(file_path.stem)
        if not turns:
            continue
        session_id = str(turns[0].get("session_id") or file_path.stem)
        start_dt = _iso_to_dt(str(turns[0].get("timestamp", "")))
        end_dt = _iso_to_dt(str(turns[-1].get("timestamp", "")))
        report_paths: set[str] = set()
        for turn in turns:
            for report_path in _coerce_string_list(turn.get("report_paths", [])):
                resolved = _resolve_report_reference(report_path)
                if resolved:
                    report_paths.add(resolved)
        rows.append(
            {
                "id": session_id,
                "start": _to_iso(start_dt) if start_dt else str(turns[0].get("timestamp", "")),
                "end": _to_iso(end_dt) if end_dt else str(turns[-1].get("timestamp", "")),
                "chat_turn_count": len(turns),
                "report_paths": sorted(report_paths),
            }
        )
    rows.sort(key=lambda s: s.get("start", ""), reverse=True)
    return rows


def _safe_rel(base: Path, value: Path) -> str:
    try:
        return str(value.resolve().relative_to(base.resolve()))
    except Exception:
        return value.name


def _resolve_report_reference(path_value: str) -> str:
    raw = str(path_value or "").strip()
    if not raw:
        return ""
    roots = [_reports_dir(), _output_dir()]
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            resolved = candidate.resolve()
        except Exception:
            return ""
        for root in roots:
            try:
                resolved.relative_to(root.resolve())
            except Exception:
                continue
            if resolved.exists() and resolved.is_file():
                return str(resolved)
        return ""

    for root in roots:
        joined = (root / raw).resolve()
        try:
            joined.relative_to(root.resolve())
        except Exception:
            continue
        if joined.exists() and joined.is_file():
            return str(joined)

    name = Path(raw).name
    fallback_matches: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        fallback_matches.extend([p.resolve() for p in root.rglob(name) if p.is_file()])
    unique_matches = sorted(set(str(p) for p in fallback_matches))
    if len(unique_matches) == 1:
        return unique_matches[0]
    return ""


def _normalize_existing_report_paths(paths: list[str]) -> list[str]:
    rows: list[str] = []
    seen: set[str] = set()
    for value in paths:
        resolved = _resolve_report_reference(value)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        rows.append(resolved)
    return rows


def _load_events(max_events: int = 20_000) -> list[dict]:
    path = _audit_log_path()
    if not path.exists():
        return []
    events: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except Exception:
                continue
    if len(events) > max_events:
        events = events[-max_events:]
    events.sort(key=lambda e: str(e.get("timestamp", "")))
    return events


def _extract_report_path_from_event(event: dict) -> str:
    payload = event.get("payload", {})
    if not isinstance(payload, dict):
        return ""
    result = payload.get("result")
    if isinstance(result, dict) and result.get("path"):
        return str(result.get("path"))
    if payload.get("path"):
        return str(payload.get("path"))
    return ""


def _collect_explicit_main_sessions(events: list[dict]) -> dict:
    by_id: dict[str, dict] = {}
    chat_to_main: dict[str, str] = {}
    ordered_ids: list[str] = []

    for event in events:
        payload = event.get("payload", {})
        payload = payload if isinstance(payload, dict) else {}
        event_type = str(event.get("event_type", "")).strip()
        ts = _iso_to_dt(str(event.get("timestamp", "")))

        if event_type == "session.start" and str(payload.get("source", "")).strip() == "explicit_tool":
            sid = str(payload.get("mcp_session_id", "")).strip() or str(payload.get("session_id", "")).strip()
            if not sid:
                continue
            chat_session_id = str(payload.get("chat_session_id", "")).strip()
            label = str(payload.get("label", "")).strip()
            if sid not in by_id:
                by_id[sid] = {
                    "session_id": sid,
                    "chat_session_id": chat_session_id,
                    "label": label,
                    "start_dt": ts,
                    "end_dt": None,
                    "start": _to_iso(ts) if ts else str(event.get("timestamp", "")),
                    "end": "",
                }
                ordered_ids.append(sid)
            else:
                # Keep earliest explicit start if duplicates occur.
                existing = by_id[sid]
                if existing.get("start_dt") is None and ts is not None:
                    existing["start_dt"] = ts
                    existing["start"] = _to_iso(ts)
                if chat_session_id and not existing.get("chat_session_id"):
                    existing["chat_session_id"] = chat_session_id
                if label and not existing.get("label"):
                    existing["label"] = label
            if chat_session_id:
                chat_to_main[chat_session_id] = sid

        if event_type == "session.end" and str(payload.get("source", "")).strip() == "explicit_tool":
            sid = str(payload.get("mcp_session_id", "")).strip() or str(payload.get("session_id", "")).strip()
            if not sid or sid not in by_id:
                continue
            by_id[sid]["end_dt"] = ts
            by_id[sid]["end"] = _to_iso(ts) if ts else str(event.get("timestamp", ""))

    return {"by_id": by_id, "chat_to_main": chat_to_main, "ordered_ids": ordered_ids}


def _nearest_open_main_session_id(ts: datetime | None, explicit_meta: dict) -> str:
    by_id = explicit_meta.get("by_id", {})
    if not isinstance(by_id, dict) or not by_id:
        return ""

    if ts is None:
        ordered_ids = explicit_meta.get("ordered_ids", [])
        if isinstance(ordered_ids, list) and ordered_ids:
            return str(ordered_ids[-1])
        return ""

    best_sid = ""
    best_start: datetime | None = None
    for sid, info in by_id.items():
        if not isinstance(info, dict):
            continue
        start_dt = info.get("start_dt")
        end_dt = info.get("end_dt")
        if start_dt is None or start_dt > ts:
            continue
        if end_dt is not None and ts > end_dt:
            continue
        if best_start is None or start_dt > best_start:
            best_sid = str(sid)
            best_start = start_dt
    return best_sid


def _resolve_main_session_id(event: dict, payload: dict, explicit_meta: dict) -> str:
    by_id = explicit_meta.get("by_id", {})
    chat_to_main = explicit_meta.get("chat_to_main", {})
    ts = _iso_to_dt(str(event.get("timestamp", "")))

    direct_main = str(payload.get("main_session_id", "")).strip()
    if direct_main and direct_main in by_id:
        return direct_main

    sid = str(payload.get("mcp_session_id", "")).strip() or str(payload.get("session_id", "")).strip()
    if sid and sid in by_id:
        return sid

    if sid and sid in chat_to_main:
        return str(chat_to_main[sid])

    chat_sid = str(payload.get("chat_session_id", "")).strip()
    if chat_sid and chat_sid in chat_to_main:
        return str(chat_to_main[chat_sid])

    event_type = str(event.get("event_type", "")).strip()
    if event_type in _SYSTEM_EVENT_TYPES:
        return ""

    return _nearest_open_main_session_id(ts, explicit_meta)


def _sessionize(events: list[dict], idle_minutes: int = 30) -> tuple[list[dict], dict[str, dict], dict]:
    sessions: list[dict] = []
    details: dict[str, dict] = {}
    explicit_meta = _collect_explicit_main_sessions(events)
    explicit_by_id = explicit_meta.get("by_id", {})

    for event in events:
        payload = event.get("payload", {})
        payload = payload if isinstance(payload, dict) else {}
        ts = _iso_to_dt(str(event.get("timestamp", "")))

        main_session_id = _resolve_main_session_id(event, payload, explicit_meta)
        if not main_session_id:
            continue

        explicit_info = explicit_by_id.get(main_session_id, {})
        if main_session_id not in details:
            start_ts = str(explicit_info.get("start") or (_to_iso(ts) if ts else event.get("timestamp", "")))
            details[main_session_id] = {
                "id": main_session_id,
                "caption": str(explicit_info.get("label") or explicit_info.get("chat_session_id") or main_session_id),
                "chat_session_id": str(explicit_info.get("chat_session_id") or ""),
                "start": start_ts,
                "end": start_ts,
                "events": [],
                "tools": set(),
                "reports": set(),
                "chat_turns": [],
            }
        bucket = details[main_session_id]

        normalized_event = dict(event)
        normalized_payload = dict(payload)
        raw_sid = str(payload.get("mcp_session_id", "")).strip() or str(payload.get("session_id", "")).strip()
        normalized_payload["main_session_id"] = main_session_id
        normalized_payload["mcp_session_id"] = raw_sid or main_session_id
        if raw_sid and raw_sid != main_session_id:
            normalized_payload["event_session_id"] = raw_sid
        normalized_event["payload"] = normalized_payload

        bucket["events"].append(normalized_event)
        bucket["end"] = _to_iso(ts) if ts else event.get("timestamp", bucket["end"])

        tool = str(normalized_payload.get("tool", "")).strip()
        if tool:
            bucket["tools"].add(tool)

        report_path = _extract_report_path_from_event(normalized_event)
        if report_path:
            bucket["reports"].add(report_path)

    for sid, info in details.items():
        evts = info["events"]
        sessions.append(
            {
                "id": sid,
                "caption": info.get("caption", sid),
                "start": info["start"],
                "end": info["end"],
                "event_count": len(evts),
                "tools": sorted(info["tools"]),
                "report_count": len(info["reports"]),
                "chat_turn_count": len(info.get("chat_turns", [])),
            }
        )
        info["tools"] = sorted(info["tools"])
        info["reports"] = sorted(info["reports"])

    sessions.sort(key=lambda s: s.get("start", ""), reverse=True)
    return sessions, details, explicit_meta


def _list_reports() -> list[dict]:
    base = _reports_dir()
    if not base.exists():
        return []
    reports: list[dict] = []
    for p in sorted(base.rglob("*"), key=lambda f: f.stat().st_mtime if f.exists() else 0, reverse=True):
        if not p.is_file():
            continue
        try:
            stat = p.stat()
            reports.append(
                {
                    "path": str(p),
                    "relative_path": _safe_rel(base, p),
                    "size_bytes": stat.st_size,
                    "modified": _to_iso(datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)),
                }
            )
        except Exception:
            continue
    return reports


def _list_output_files() -> list[dict]:
    base = _output_dir()
    if not base.exists():
        return []
    files: list[dict] = []
    for p in sorted(base.rglob("*"), key=lambda f: f.stat().st_mtime if f.exists() else 0, reverse=True):
        if not p.is_file():
            continue
        try:
            stat = p.stat()
            files.append(
                {
                    "path": str(p),
                    "relative_path": _safe_rel(base, p),
                    "size_bytes": stat.st_size,
                    "modified": _to_iso(datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)),
                }
            )
        except Exception:
            continue
    return files


def _read_text_file(path_value: str, allowed_bases: list[Path], max_chars: int = 250_000) -> dict:
    ok, resolved, error = _resolve_allowed_file(path_value, allowed_bases)
    if not ok or resolved is None:
        return {"success": False, "error": error}

    content = resolved.read_text(encoding="utf-8", errors="replace")
    if len(content) > max_chars:
        content = content[:max_chars] + f"\n... [truncated {len(content) - max_chars} chars]"
    return {"success": True, "path": str(resolved), "content": content}


def _resolve_allowed_file(path_value: str, allowed_bases: list[Path]) -> tuple[bool, Path | None, str]:
    target = Path(path_value)
    try:
        resolved = target.resolve()
    except Exception:
        return False, None, "Invalid path"
    allowed = False
    for base in allowed_bases:
        try:
            resolved.relative_to(base.resolve())
            allowed = True
            break
        except Exception:
            continue
    if not allowed:
        return False, None, "Path is outside allowed directories"
    if not resolved.exists() or not resolved.is_file():
        return False, None, f"File not found: {resolved}"
    return True, resolved, ""


def _is_inline_preview(content_type: str, path_obj: Path) -> bool:
    ctype = str(content_type or "").lower()
    ext = path_obj.suffix.lower()
    if ctype.startswith("text/"):
        return True
    if ctype in {"application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"}:
        return True
    if ext in {".html", ".htm", ".pdf", ".txt", ".log", ".json", ".csv", ".md", ".xml", ".yaml", ".yml"}:
        return True
    return False


def _build_dashboard_state() -> dict:
    events = _load_events()
    sessions, details, explicit_meta = _sessionize(events)
    _merge_chat_sessions(sessions, details, _list_chat_sessions(), explicit_meta)
    reports = _list_reports()
    _associate_reports_to_sessions(sessions, details, reports)
    output_files = _list_output_files()
    return {
        "generated_at": _to_iso(now_tz()),
        "audit_log_path": str(_audit_log_path()),
        "sessions": sessions,
        "session_details": details,
        "reports": reports,
        "output_files": output_files,
    }


def _merge_chat_sessions(
    sessions: list[dict],
    details: dict[str, dict],
    chat_sessions: list[dict],
    explicit_meta: dict,
) -> None:
    by_id: dict[str, dict] = {str(row.get("id", "")): row for row in sessions}
    chat_to_main = explicit_meta.get("chat_to_main", {})
    explicit_by_id = explicit_meta.get("by_id", {})

    for row in sessions:
        row["chat_turn_count"] = int(row.get("chat_turn_count", 0))
    for info in details.values():
        if not isinstance(info.get("chat_turns"), list):
            info["chat_turns"] = []

    for chat in chat_sessions:
        sid = str(chat.get("id", "")).strip()
        if not sid:
            continue
        target_sid = str(chat_to_main.get(sid, "")).strip()
        turns = _load_chat_turns(sid)
        if not target_sid:
            for turn in turns:
                metadata = turn.get("metadata", {})
                if not isinstance(metadata, dict):
                    continue
                for key in ("session_uuid", "main_session_id"):
                    candidate = str(metadata.get(key, "")).strip()
                    if candidate and candidate in explicit_by_id:
                        target_sid = candidate
                        break
                if target_sid:
                    break
        if not target_sid and sid in details:
            target_sid = sid
        if not target_sid:
            start_dt = _iso_to_dt(str(chat.get("start", "")))
            target_sid = _nearest_open_main_session_id(start_dt, explicit_meta)
        if not target_sid:
            continue
        turns = [{**t, "report_paths": _normalize_existing_report_paths(_coerce_string_list(t.get("report_paths", [])))} for t in turns]
        start = str(chat.get("start", ""))
        end = str(chat.get("end", ""))
        report_paths = _normalize_existing_report_paths(_coerce_string_list(chat.get("report_paths", [])))

        if target_sid not in details:
            details[target_sid] = {
                "id": target_sid,
                "caption": target_sid,
                "chat_session_id": sid,
                "start": start,
                "end": end,
                "events": [],
                "tools": [],
                "reports": report_paths[:],
                "chat_turns": turns,
            }
        else:
            details[target_sid]["chat_turns"] = turns
            if not details[target_sid].get("chat_session_id"):
                details[target_sid]["chat_session_id"] = sid
            existing_reports = details[target_sid].get("reports", [])
            if isinstance(existing_reports, set):
                details[target_sid]["reports"] = sorted(set(str(x) for x in existing_reports).union(report_paths))
            else:
                details[target_sid]["reports"] = sorted(set(_coerce_string_list(existing_reports) + report_paths))
            if start and (not details[target_sid].get("start") or start < str(details[target_sid].get("start", ""))):
                details[target_sid]["start"] = start
            if end and (not details[target_sid].get("end") or end > str(details[target_sid].get("end", ""))):
                details[target_sid]["end"] = end

        row = by_id.get(target_sid)
        if not row:
            # Keep left panel restricted to explicit/main sessions only.
            continue
        else:
            row["chat_turn_count"] = len(turns)
            row["report_count"] = len(set(_coerce_string_list(details[target_sid].get("reports", []))))
            if details[target_sid].get("start"):
                row["start"] = details[target_sid]["start"]
            if details[target_sid].get("end"):
                row["end"] = details[target_sid]["end"]
            if details[target_sid].get("caption"):
                row["caption"] = details[target_sid]["caption"]

    sessions.sort(key=lambda s: s.get("start", ""), reverse=True)


def _associate_reports_to_sessions(sessions: list[dict], details: dict[str, dict], reports: list[dict]) -> None:
    """Backfill report-to-session links by file timestamp proximity.

    This helps when report path wasn't captured in the same event payload.
    """
    linked_paths: set[str] = set()
    for info in details.values():
        for p in info.get("reports", []):
            linked_paths.add(str(p))

    lead = timedelta(minutes=2)
    lag = timedelta(minutes=5)

    for report in reports:
        path = str(report.get("path", ""))
        if not path or path in linked_paths:
            continue
        path_parts = set(Path(path).parts)
        direct_sid = next((sid for sid in details.keys() if sid and sid in path_parts), "")
        if direct_sid:
            details[direct_sid]["reports"].append(path)
            linked_paths.add(path)
            continue
        report_dt = _iso_to_dt(str(report.get("modified", "")))
        if report_dt is None:
            continue

        best_sid = ""
        best_gap = None
        for sid, info in details.items():
            start_dt = _iso_to_dt(str(info.get("start", "")))
            end_dt = _iso_to_dt(str(info.get("end", "")))
            if start_dt is None or end_dt is None:
                continue
            if report_dt < (start_dt - lead) or report_dt > (end_dt + lag):
                continue
            gap = abs((report_dt - end_dt).total_seconds())
            if best_gap is None or gap < best_gap:
                best_gap = gap
                best_sid = sid

        if best_sid:
            details[best_sid]["reports"].append(path)
            linked_paths.add(path)

    for sid, info in details.items():
        unique_sorted = sorted(set(str(p) for p in info.get("reports", [])))
        info["reports"] = unique_sorted
        for row in sessions:
            if row.get("id") == sid:
                row["report_count"] = len(unique_sorted)
                break


def _dashboard_html() -> str:
    static_html = _read_dashboard_asset("index.html")
    if static_html:
        return static_html
    raise RuntimeError(
        "Dashboard asset missing: tools/dashboard_assets/index.html. "
        "Ensure dashboard static assets are present in the runtime image."
    )


def _login_html(error_message: str = "", subscription_status: dict | None = None) -> str:
    safe_error = html.escape(str(error_message or ""))
    error_block = (
        f'<div style="color:#fca5a5;margin-bottom:10px;">{safe_error}</div>'
        if safe_error else ""
    )
    status = subscription_status if isinstance(subscription_status, dict) else get_subscription_status()
    status_state = str(status.get("state", "unknown")).strip().lower()
    banner_bg = "#052e16"
    banner_border = "#166534"
    banner_color = "#bbf7d0"
    if status_state in {"missing", "expired", "invalid", "not_started"}:
        banner_bg = "#3f1d1d"
        banner_border = "#7f1d1d"
        banner_color = "#fecaca"
    banner_msg = html.escape(str(status.get("message", "Subscription state unavailable")))
    banner_sub = html.escape(str(status.get("subscriber_name", "")).strip())
    banner_end = html.escape(str(status.get("subscription_end_date", "")).strip())
    banner_meta = []
    if banner_sub:
        banner_meta.append(f"Subscriber: {banner_sub}")
    if banner_end:
        banner_meta.append(f"End: {banner_end}")
    banner_meta_html = f'<div class="sub-banner-meta">{" | ".join(banner_meta)}</div>' if banner_meta else ""
    subscription_block = (
        f'<div class="sub-banner" style="background:{banner_bg};border-color:{banner_border};color:{banner_color};">'
        f"<strong>Subscription Status:</strong> {banner_msg}{banner_meta_html}</div>"
    )
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Cybertool Dashboard Login</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }}
    .card {{ width: 360px; background:#111827; border:1px solid #334155; border-radius:10px; padding:20px; }}
    label {{ display:block; margin-bottom:6px; font-size:13px; color:#94a3b8; }}
    input {{ width:100%; box-sizing:border-box; margin-bottom:12px; padding:8px 10px; background:#020617; border:1px solid #334155; color:#e2e8f0; border-radius:6px; }}
    button {{ width:100%; background:#1d4ed8; color:#fff; border:none; border-radius:6px; padding:10px; cursor:pointer; }}
    .muted {{ color:#94a3b8; font-size:12px; margin-top:10px; }}
    .sub-banner {{ border:1px solid; border-radius:8px; padding:10px; margin:0 0 12px 0; font-size:13px; line-height:1.4; }}
    .sub-banner-meta {{ margin-top:6px; font-size:12px; opacity:0.95; }}
  </style>
</head>
<body>
  <div class="card">
    <h2 style="margin-top:0;">Dashboard Login</h2>
    {subscription_block}
    {error_block}
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" autocomplete="username" required />
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required />
      <button type="submit">Sign In</button>
    </form>
    <div class="muted">Access is restricted to configured dashboard credentials.</div>
  </div>
</body>
</html>"""


class _DashboardHandler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict):
        blob = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def _html(self, status: int, content: str):
        blob = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def _asset(self, status: int, data: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _parse_form(self) -> dict[str, str]:
        content_length_raw = self.headers.get("Content-Length", "0").strip()
        try:
            content_length = int(content_length_raw)
        except ValueError:
            content_length = 0
        body = self.rfile.read(max(0, content_length)).decode("utf-8", errors="replace")
        parsed = parse_qs(body)
        return {k: (v[0] if v else "") for k, v in parsed.items()}

    def _unauthorized(self):
        payload = {"success": False, "error": "Unauthorized dashboard access"}
        blob = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(401)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("WWW-Authenticate", "Bearer")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def log_message(self, format: str, *args):  # noqa: A003
        return

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/login":
            if not _login_auth_enabled():
                return self._redirect("/")
            if _authorized_via_login_cookie(self.headers):
                return self._redirect("/")
            return self._html(200, _login_html(subscription_status=get_subscription_status()))

        if path == "/logout":
            cookies = _parse_cookie_header(self.headers.get("Cookie", ""))
            sid = cookies.get(_SESSION_COOKIE_NAME, "")
            if sid:
                _clear_session(sid)
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header(
                "Set-Cookie",
                f"{_SESSION_COOKIE_NAME}=deleted; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            )
            self.end_headers()
            return

        if not _is_authorized(self.headers, query):
            if path.startswith("/api/"):
                return self._unauthorized()
            if _login_auth_enabled():
                return self._redirect("/login")
            return self._unauthorized()

        if path.startswith("/assets/"):
            asset_name = path.rsplit("/", 1)[-1]
            try:
                asset_path = _dashboard_asset_path(asset_name)
            except Exception:
                return self._json(404, {"success": False, "error": "Not found"})
            if not asset_path.exists() or not asset_path.is_file():
                return self._json(404, {"success": False, "error": "Not found"})
            ctype, _ = mimetypes.guess_type(str(asset_path))
            ctype = ctype or "application/octet-stream"
            return self._asset(200, asset_path.read_bytes(), ctype)

        if path == "/":
            return self._html(200, _dashboard_html())

        if path == "/api/sessions":
            state = _build_dashboard_state()
            return self._json(
                200,
                {
                    "generated_at": state["generated_at"],
                    "audit_log_path": state["audit_log_path"],
                    "sessions": state["sessions"],
                },
            )

        if path.startswith("/api/sessions/"):
            session_id = path.rsplit("/", 1)[-1]
            state = _build_dashboard_state()
            detail = state["session_details"].get(session_id)
            if not detail:
                return self._json(404, {"success": False, "error": f"Unknown session: {session_id}"})
            flow_groups = _build_session_flow_groups(detail.get("events", []))
            return self._json(
                200,
                {
                    "success": True,
                    "session": {
                        "id": detail["id"],
                        "caption": detail.get("caption", detail["id"]),
                        "start": _normalize_timestamp_text(str(detail["start"])),
                        "end": _normalize_timestamp_text(str(detail["end"])),
                        "event_count": len(detail["events"]),
                        "tools": detail["tools"],
                        "reports": detail["reports"],
                        "chat_turns": [_normalize_chat_turn_for_display(t) for t in detail.get("chat_turns", [])],
                        "flow_groups": flow_groups,
                    },
                },
            )

        if path == "/api/reports":
            return self._json(200, {"success": True, "reports": _list_reports()})

        if path == "/api/output-files":
            return self._json(200, {"success": True, "files": _list_output_files()})

        if path == "/api/subscription/status":
            return self._json(200, {"success": True, "subscription": get_subscription_status()})

        if path == "/api/playbooks":
            ensure_playbook_store()
            return self._json(
                200,
                {
                    "success": True,
                    "playbooks": list_playbooks(),
                    "playbooks_dir": os.environ.get("MCP_PLAYBOOKS_DIR", "/opt/uts-mcp/data/playbooks"),
                },
            )

        if path.startswith("/api/playbooks/") and path.endswith("/runs"):
            parts = path.split("/")
            if len(parts) >= 5:
                name = parts[3]
                limit_raw = str((query.get("limit") or ["50"])[0]).strip()
                try:
                    limit = max(1, min(500, int(limit_raw)))
                except ValueError:
                    limit = 50
                return self._json(200, {"success": True, "runs": list_playbook_runs(name, limit=limit)})

        if path.startswith("/api/playbooks/") and not path.endswith("/validate"):
            name = path.rsplit("/", 1)[-1]
            try:
                return self._json(200, {"success": True, **get_playbook(name)})
            except Exception as exc:
                return self._json(404, {"success": False, "error": str(exc)})

        if path == "/api/file":
            requested = (query.get("path") or [""])[0]
            result = _read_text_file(
                requested,
                allowed_bases=[_reports_dir(), _output_dir(), Path("/opt/uts-mcp/logs")],
            )
            return self._json(200 if result.get("success") else 400, result)

        if path == "/file/view":
            requested = (query.get("path") or [""])[0]
            allowed_bases = [_reports_dir(), _output_dir(), Path("/opt/uts-mcp/logs")]
            ok, resolved, error = _resolve_allowed_file(requested, allowed_bases)
            if not ok or resolved is None:
                return self._json(400, {"success": False, "error": error})

            data = resolved.read_bytes()
            content_type, _ = mimetypes.guess_type(str(resolved))
            content_type = content_type or "application/octet-stream"
            disposition = "inline" if _is_inline_preview(content_type, resolved) else "attachment"

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f'{disposition}; filename="{resolved.name}"')
            self.end_headers()
            self.wfile.write(data)
            return

        return self._json(404, {"success": False, "error": "Not found"})

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path != "/login":
            if path == "/api/subscription/upload":
                if not _is_authorized(self.headers, parse_qs(urlparse(self.path).query)):
                    return self._unauthorized()
                filename = str(self.headers.get("X-Subscription-Filename", "subscription.lic")).strip() or "subscription.lic"
                if not filename.lower().endswith(".lic"):
                    return self._json(
                        400,
                        {"success": False, "error": "Uploaded file must use .lic extension"},
                    )
                try:
                    content_length = int(self.headers.get("Content-Length", "0").strip() or "0")
                except ValueError:
                    content_length = 0
                raw = self.rfile.read(max(0, content_length))
                if not raw:
                    return self._json(400, {"success": False, "error": "Upload body is empty"})
                if len(raw) > _MAX_SUBSCRIPTION_UPLOAD_BYTES:
                    return self._json(400, {"success": False, "error": "Subscription file exceeds 128KB limit"})
                target = subscription_license_path()
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    temp_path = target.with_suffix(f"{target.suffix}.tmp")
                    temp_path.write_bytes(raw)
                    temp_path.replace(target)
                    invalidate_subscription_cache()
                except OSError as exc:
                    return self._json(
                        500,
                        {"success": False, "error": f"Failed to store subscription file: {exc}"},
                    )
                return self._json(
                    200,
                    {
                        "success": True,
                        "subscription": get_subscription_status(force_refresh=True),
                        "path": str(target),
                    },
                )

            if path == "/api/playbooks":
                if not _is_authorized(self.headers, parse_qs(urlparse(self.path).query)):
                    return self._unauthorized()
                try:
                    content_length = int(self.headers.get("Content-Length", "0").strip() or "0")
                except ValueError:
                    content_length = 0
                body = self.rfile.read(max(0, content_length)).decode("utf-8", errors="replace")
                try:
                    payload = json.loads(body or "{}")
                except Exception:
                    payload = {}
                name = str(payload.get("name", "")).strip()
                content = str(payload.get("content", ""))
                expected_version_raw = payload.get("expected_version")
                expected_version = None
                if expected_version_raw is not None:
                    try:
                        expected_version = int(expected_version_raw)
                    except ValueError:
                        expected_version = None
                return self._json(200, create_or_update_playbook(name, content, expected_version=expected_version))

            if path.startswith("/api/playbooks/"):
                if not _is_authorized(self.headers, parse_qs(urlparse(self.path).query)):
                    return self._unauthorized()
                parts = path.split("/")
                if len(parts) < 4:
                    return self._json(404, {"success": False, "error": "Not found"})
                name = parts[3]
                action = parts[4] if len(parts) > 4 else ""
                try:
                    content_length = int(self.headers.get("Content-Length", "0").strip() or "0")
                except ValueError:
                    content_length = 0
                body = self.rfile.read(max(0, content_length)).decode("utf-8", errors="replace")
                try:
                    payload = json.loads(body or "{}")
                except Exception:
                    payload = {}

                if action == "clone":
                    target_name = str(payload.get("target_name", "")).strip()
                    return self._json(200, clone_playbook(name, target_name))
                if action == "validate":
                    content = str(payload.get("content", ""))
                    return self._json(200, {"success": True, "name": name, **validate_playbook_yaml(content)})
                if action == "run":
                    return self._json(
                        400,
                        {
                            "success": False,
                            "error": "Dashboard playbook run is disabled. Execute playbooks from AI chat using run_playbook.",
                            "hint": f'run_playbook(name="{name}", target="<target>", variables_json="{{}}")',
                        },
                    )

            return self._json(404, {"success": False, "error": "Not found"})
        if not _login_auth_enabled():
            return self._json(400, {"success": False, "error": "Login auth is not enabled"})

        client_ip = _client_ip(self.headers, self.client_address)
        locked, remaining = _is_login_locked(client_ip)
        if locked:
            return self._html(
                429,
                _login_html(f"Too many failed attempts. Try again in {remaining} seconds."),
            )

        form = self._parse_form()
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", "")).strip()
        if username != _dashboard_username() or not _verify_password(password):
            locked_now, lockout_seconds = _record_login_failure(client_ip)
            if locked_now:
                return self._html(
                    429,
                    _login_html(
                        f"Too many failed attempts. Account locked for {lockout_seconds} seconds."
                    ),
                )
            return self._html(401, _login_html("Invalid username or password"))

        _clear_login_failures(client_ip)
        sid, expiry = _issue_session()
        secure_attr = "; Secure" if _cookie_secure_enabled() else ""
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            (
                f"{_SESSION_COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Lax; "
                f"Max-Age={_SESSION_TTL_SECONDS}; Expires={expiry.astimezone(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}"
                f"{secure_attr}"
            ),
        )
        self.end_headers()

    def do_PUT(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if not _is_authorized(self.headers, query):
            return self._unauthorized()
        if not path.startswith("/api/playbooks/"):
            return self._json(404, {"success": False, "error": "Not found"})
        name = path.rsplit("/", 1)[-1]
        try:
            content_length = int(self.headers.get("Content-Length", "0").strip() or "0")
        except ValueError:
            content_length = 0
        body = self.rfile.read(max(0, content_length)).decode("utf-8", errors="replace")
        try:
            payload = json.loads(body or "{}")
        except Exception:
            payload = {}
        content = str(payload.get("content", ""))
        expected_version_raw = payload.get("expected_version")
        expected_version = None
        if expected_version_raw is not None:
            try:
                expected_version = int(expected_version_raw)
            except ValueError:
                expected_version = None
        return self._json(200, create_or_update_playbook(name, content, expected_version=expected_version))

    def do_DELETE(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if not _is_authorized(self.headers, query):
            return self._unauthorized()
        if not path.startswith("/api/playbooks/"):
            return self._json(404, {"success": False, "error": "Not found"})
        name = path.rsplit("/", 1)[-1]
        soft_delete_raw = str((query.get("soft_delete") or ["true"])[0]).strip().lower()
        soft_delete = soft_delete_raw not in {"0", "false", "no", "off"}
        return self._json(200, delete_playbook(name, soft_delete=soft_delete))


def start_dashboard_server(mcp_instance=None) -> None:
    """Start dashboard server in a background daemon thread (idempotent)."""
    global _STARTED
    global _MCP_INSTANCE
    _MCP_INSTANCE = mcp_instance

    ensure_playbook_store()

    backend = os.environ.get("MCP_DASHBOARD_BACKEND", "legacy").strip().lower()
    if backend == "legacy":
        _validate_dashboard_assets_or_raise()
    if backend == "fastapi":
        from tools.dashboard_fastapi import start_fastapi_dashboard_server

        start_fastapi_dashboard_server(mcp_instance)
        write_audit_event(
            "dashboard.listen",
            {
                "backend": "fastapi",
                "host": os.environ.get("MCP_DASHBOARD_HOST", "0.0.0.0"),
                "port": os.environ.get("MCP_DASHBOARD_PORT", "8090"),
                "audit_log_path": str(_audit_log_path()),
                "reports_dir": str(_reports_dir()),
                "chat_history_dir": str(_chat_history_dir()),
                "playbooks_dir": os.environ.get("MCP_PLAYBOOKS_DIR", "/opt/uts-mcp/data/playbooks"),
            },
        )
        return

    with _LOCK:
        if _STARTED:
            return
        _STARTED = True

    host = os.environ.get("MCP_DASHBOARD_HOST", "0.0.0.0").strip() or "0.0.0.0"
    raw_port = os.environ.get("MCP_DASHBOARD_PORT", "8090").strip()
    try:
        port = int(raw_port)
    except ValueError:
        port = 8090

    server = ThreadingHTTPServer((host, port), _DashboardHandler)

    thread = threading.Thread(target=server.serve_forever, name="mcp-dashboard-server", daemon=True)
    thread.start()

    write_audit_event(
        "dashboard.listen",
        {
            "host": host,
            "port": port,
            "audit_log_path": str(_audit_log_path()),
            "reports_dir": str(_reports_dir()),
            "chat_history_dir": str(_chat_history_dir()),
            "playbooks_dir": os.environ.get("MCP_PLAYBOOKS_DIR", "/opt/uts-mcp/data/playbooks"),
            "backend": "legacy",
        },
    )
