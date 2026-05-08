"""Session finalization helpers for report capture and archival."""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from tools.reporting import REPORT_DIR, _allocate_report_run_dir

_DEFAULT_AUDIT_PATH = "/opt/uts-mcp/logs/mcp_audit.jsonl"
_DEFAULT_REPORTS_DIR = "/opt/uts-mcp/reports"
_DEFAULT_OUTPUT_DIR = "/opt/uts-mcp/output"
_DEFAULT_CHAT_HISTORY_DIR = "/opt/uts-mcp/logs/chat_sessions"
_CHAT_MAIN_KEYS = ("session_uuid", "main_session_id", "session_id")
_REPORT_EXTS = {".html", ".pdf", ".docx"}
_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _audit_log_path() -> Path:
    raw = os.environ.get("MCP_AUDIT_LOG_PATH", _DEFAULT_AUDIT_PATH).strip()
    return Path(raw or _DEFAULT_AUDIT_PATH)


def _output_dir() -> Path:
    raw = os.environ.get("MCP_OUTPUT_DIR", _DEFAULT_OUTPUT_DIR).strip()
    return Path(raw or _DEFAULT_OUTPUT_DIR)


def _reports_dir() -> Path:
    raw = os.environ.get("MCP_REPORTS_DIR", _DEFAULT_REPORTS_DIR).strip()
    return Path(raw or _DEFAULT_REPORTS_DIR)


def _chat_history_dir() -> Path:
    raw = os.environ.get("MCP_CHAT_HISTORY_DIR", _DEFAULT_CHAT_HISTORY_DIR).strip()
    return Path(raw or _DEFAULT_CHAT_HISTORY_DIR)


def _safe_segment(value: str) -> str:
    cleaned = _SAFE_SEGMENT_RE.sub("_", str(value or "").strip()).strip("._")
    return cleaned[:128] if cleaned else ""


def _parse_iso(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _coerce_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    rows: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if text:
            rows.append(text)
    return rows


def _load_chat_turns(chat_session_id: str) -> list[dict]:
    key = _safe_segment(chat_session_id)
    if not key:
        return []
    path = _chat_history_dir() / f"{key}.jsonl"
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
    turns.sort(key=lambda t: str(t.get("timestamp", "")))
    return turns


def _discover_chat_session_ids_from_audit(main_session_id: str) -> set[str]:
    path = _audit_log_path()
    if not path.exists():
        return set()
    found: set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            payload = event.get("payload", {})
            if not isinstance(payload, dict):
                continue
            direct_sid = str(payload.get("mcp_session_id", "")).strip() or str(payload.get("session_id", "")).strip()
            main_sid = str(payload.get("main_session_id", "")).strip()
            if direct_sid != main_session_id and main_sid != main_session_id:
                continue
            chat_sid = str(payload.get("chat_session_id", "")).strip()
            if chat_sid:
                found.add(chat_sid)
            args = payload.get("args", {})
            if isinstance(args, dict):
                args_chat_sid = str(args.get("chat_session_id", "")).strip()
                if args_chat_sid:
                    found.add(args_chat_sid)
    return found


def _discover_chat_session_ids_from_chat_files(main_session_id: str) -> set[str]:
    base = _chat_history_dir()
    if not base.exists():
        return set()
    found: set[str] = set()
    for path in base.glob("*.jsonl"):
        turns = _load_chat_turns(path.stem)
        for turn in turns:
            metadata = turn.get("metadata", {})
            if not isinstance(metadata, dict):
                continue
            for key in _CHAT_MAIN_KEYS:
                if str(metadata.get(key, "")).strip() == main_session_id:
                    found.add(path.stem)
                    break
            if path.stem in found:
                break
    return found


def _session_window_from_audit(main_session_id: str) -> tuple[datetime | None, datetime | None]:
    path = _audit_log_path()
    if not path.exists():
        return None, None
    start_dt: datetime | None = None
    end_dt: datetime | None = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            payload = event.get("payload", {})
            if not isinstance(payload, dict):
                continue
            direct_sid = str(payload.get("mcp_session_id", "")).strip() or str(payload.get("session_id", "")).strip()
            if direct_sid != main_session_id and str(payload.get("main_session_id", "")).strip() != main_session_id:
                continue
            ts = _parse_iso(str(event.get("timestamp", "")))
            if ts is None:
                continue
            if start_dt is None or ts < start_dt:
                start_dt = ts
            if end_dt is None or ts > end_dt:
                end_dt = ts
    return start_dt, end_dt


def _window_bounds(start_dt: datetime | None, end_dt: datetime | None) -> tuple[datetime, datetime]:
    if start_dt is None or end_dt is None:
        now = datetime.now(timezone.utc)
        return now - timedelta(hours=2), now + timedelta(minutes=5)
    return start_dt - timedelta(minutes=5), end_dt + timedelta(minutes=10)


def _resolve_reference_path(
    reference: str,
    start_dt: datetime | None,
    end_dt: datetime | None,
) -> tuple[Path | None, str, str]:
    raw = str(reference or "").strip()
    if not raw:
        return None, "empty", ""
    candidate = Path(raw)
    if candidate.is_absolute() and candidate.exists() and candidate.is_file():
        resolved = candidate.resolve()
        for root in (_reports_dir(), _output_dir()):
            try:
                resolved.relative_to(root.resolve())
            except Exception:
                continue
            return resolved, "", "absolute"
        return None, f"outside_allowed:{raw}", ""

    roots = [_reports_dir(), _output_dir()]
    for root in roots:
        joined = (root / raw).resolve()
        try:
            joined.relative_to(root.resolve())
        except Exception:
            continue
        if joined.exists() and joined.is_file():
            return joined, "", "root_relative"

    basename = Path(raw).name
    lower, upper = _window_bounds(start_dt, end_dt)
    candidates: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob(basename):
            if not path.is_file():
                continue
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if lower <= mtime <= upper:
                candidates.append(path.resolve())

    unique = sorted(set(str(p) for p in candidates))
    if len(unique) == 1:
        return Path(unique[0]), "", "basename_unique"
    if len(unique) > 1:
        return None, f"ambiguous:{raw}", ""
    return None, f"missing:{raw}", ""


def _scan_output_window(start_dt: datetime | None, end_dt: datetime | None) -> list[Path]:
    base = _output_dir()
    if not base.exists():
        return []
    start_dt, end_dt = _window_bounds(start_dt, end_dt)

    rows: list[Path] = []
    for path in base.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _REPORT_EXTS:
            continue
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        if start_dt <= mtime <= end_dt:
            rows.append(path.resolve())
    rows.sort(key=lambda p: p.stat().st_mtime)
    return rows


def _unique_dest_path(run_dir: Path, filename: str) -> Path:
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    target = run_dir / filename
    index = 1
    while target.exists():
        target = run_dir / f"{stem}_{index}{suffix}"
        index += 1
    return target


def finalize_session_reports(main_session_id: str, chat_session_ids: list[str] | None = None) -> dict[str, Any]:
    sid = str(main_session_id or "").strip()
    if not sid:
        return {"success": False, "error": "session_id is required"}

    discovered: set[str] = set(_coerce_string_list(chat_session_ids or []))
    discovered.update(_discover_chat_session_ids_from_audit(sid))
    discovered.update(_discover_chat_session_ids_from_chat_files(sid))

    refs: list[str] = []
    start_dt: datetime | None = None
    end_dt: datetime | None = None
    for chat_sid in sorted(discovered):
        turns = _load_chat_turns(chat_sid)
        for turn in turns:
            refs.extend(_coerce_string_list(turn.get("report_paths", [])))
            turn_dt = _parse_iso(str(turn.get("timestamp", "")))
            if turn_dt is not None:
                if start_dt is None or turn_dt < start_dt:
                    start_dt = turn_dt
                if end_dt is None or turn_dt > end_dt:
                    end_dt = turn_dt

    if start_dt is None or end_dt is None:
        audit_start, audit_end = _session_window_from_audit(sid)
        start_dt = start_dt or audit_start
        end_dt = end_dt or audit_end

    resolved_paths: list[Path] = []
    resolved_info: list[dict[str, str]] = []
    skipped_missing: list[str] = []
    for reference in refs:
        resolved, error, resolved_by = _resolve_reference_path(reference, start_dt, end_dt)
        if resolved is None:
            if error:
                skipped_missing.append(reference)
            continue
        resolved_paths.append(resolved)
        resolved_info.append(
            {
                "reference": reference,
                "source_path": str(resolved),
                "resolved_by": resolved_by,
            }
        )

    scanned_output = _scan_output_window(start_dt, end_dt)
    resolved_paths.extend(scanned_output)
    for scanned in scanned_output:
        resolved_info.append(
            {
                "reference": str(scanned.name),
                "source_path": str(scanned),
                "resolved_by": "output_window_scan",
            }
        )

    unique_sources: list[Path] = []
    seen_sources: set[str] = set()
    for src in resolved_paths:
        key = str(src.resolve())
        if key in seen_sources:
            continue
        seen_sources.add(key)
        unique_sources.append(src.resolve())

    reports_base = _reports_dir()
    if reports_base.resolve() == REPORT_DIR.resolve():
        run_dir = _allocate_report_run_dir(sid)
    else:
        start_token = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        run_dir = reports_base / _safe_segment(sid) / start_token
        run_dir.mkdir(parents=True, exist_ok=True)
    copied_paths: list[str] = []
    skipped_empty: list[str] = []
    for src in unique_sources:
        try:
            if src.stat().st_size <= 0:
                skipped_empty.append(str(src))
                continue
        except Exception:
            skipped_missing.append(str(src))
            continue
        target = _unique_dest_path(run_dir, src.name)
        shutil.copy2(src, target)
        copied_paths.append(str(target))

    return {
        "success": True,
        "session_id": sid,
        "chat_session_ids": sorted(discovered),
        "run_directory": str(run_dir),
        "copied": copied_paths,
        "skipped_missing": sorted(set(skipped_missing)),
        "skipped_empty": sorted(set(skipped_empty)),
        "source_count": len(unique_sources),
        "resolved": resolved_info,
    }
