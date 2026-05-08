"""Tools for persisting full chat session history."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import threading
import uuid
from pathlib import Path
from typing import Any

from tools.audit_logger import audit_context, write_audit_event
from tools.reporting import REPORT_DIR, _allocate_report_run_dir
from tools.time_utils import iso_now_tz

_LOCK = threading.Lock()
_DEFAULT_CHAT_HISTORY_DIR = "/opt/uts-mcp/logs/chat_sessions"
_ALLOWED_BINARY_REPORT_EXTS = {".html", ".pdf", ".docx"}


def _chat_history_dir() -> Path:
    raw = os.environ.get("MCP_CHAT_HISTORY_DIR", _DEFAULT_CHAT_HISTORY_DIR).strip()
    return Path(raw or _DEFAULT_CHAT_HISTORY_DIR)


def _now_iso() -> str:
    return iso_now_tz()


def _safe_session_key(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    cleaned = cleaned.strip("._")
    return cleaned[:128] if cleaned else ""


def _session_path(chat_session_id: str) -> Path:
    key = _safe_session_key(chat_session_id)
    if not key:
        raise ValueError("chat_session_id must include at least one safe character")
    return _chat_history_dir() / f"{key}.jsonl"


def _safe_report_filename(filename: str) -> str:
    base = Path(str(filename or "").strip()).name
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    suffix = Path(safe).suffix.lower()
    if not safe or suffix not in _ALLOWED_BINARY_REPORT_EXTS:
        return ""
    return safe[:180]


def _resolve_report_run_dir(session_id: str, run_directory: str) -> tuple[Path | None, str]:
    base_dir = Path(os.environ.get("MCP_REPORTS_DIR", str(REPORT_DIR)).strip() or str(REPORT_DIR))
    requested_raw = str(run_directory or "").strip()
    requested = Path(requested_raw) if requested_raw else None
    if requested is not None:
        try:
            resolved = requested.resolve()
            resolved.relative_to(base_dir.resolve())
        except Exception:
            return None, "run_directory must be inside /opt/uts-mcp/reports"
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved, ""
    if base_dir.resolve() == REPORT_DIR.resolve():
        return _allocate_report_run_dir(session_id), ""
    stamp = iso_now_tz().replace(":", "").replace("-", "")[:15]
    run_dir = base_dir / _safe_session_key(session_id) / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir, ""


def _parse_json_like(raw: str, default: Any) -> tuple[Any, str]:
    text = str(raw or "").strip()
    if not text:
        return default, ""
    try:
        return json.loads(text), ""
    except Exception as exc:
        return None, str(exc)


def _coerce_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        item_text = str(item or "").strip()
        if item_text:
            result.append(item_text)
    return result


def _extract_main_session_id(metadata: dict[str, Any]) -> str:
    if not isinstance(metadata, dict):
        return ""
    for key in ("main_session_id", "session_uuid", "session_id"):
        candidate = str(metadata.get(key, "")).strip()
        if candidate:
            return candidate
    return ""


def persist_chat_turn(
    *,
    chat_session_id: str,
    user_message: str,
    assistant_message: str,
    tool_calls_json: str = "[]",
    report_paths_json: str = "[]",
    metadata_json: str = "{}",
    turn_id: str = "",
    default_main_session_id: str = "",
    audit_tool_name: str = "save_chat_exchange",
) -> dict[str, Any]:
    sid = str(chat_session_id or "").strip()
    if not sid:
        return {"success": False, "error": "chat_session_id is required"}

    tool_calls, tool_err = _parse_json_like(tool_calls_json, [])
    if tool_err:
        return {"success": False, "error": f"Invalid tool_calls_json: {tool_err}"}
    if not isinstance(tool_calls, list):
        return {"success": False, "error": "tool_calls_json must decode to a JSON array"}

    report_paths_raw, report_err = _parse_json_like(report_paths_json, [])
    if report_err:
        return {"success": False, "error": f"Invalid report_paths_json: {report_err}"}
    report_paths = _coerce_string_list(report_paths_raw)

    metadata, meta_err = _parse_json_like(metadata_json, {})
    if meta_err:
        return {"success": False, "error": f"Invalid metadata_json: {meta_err}"}
    if not isinstance(metadata, dict):
        return {"success": False, "error": "metadata_json must decode to a JSON object"}

    fallback_main_sid = str(default_main_session_id or "").strip()
    if fallback_main_sid and not str(metadata.get("main_session_id", "")).strip():
        metadata["main_session_id"] = fallback_main_sid

    entry = {
        "timestamp": _now_iso(),
        "turn_id": str(turn_id or f"turn-{uuid.uuid4().hex[:12]}"),
        "session_id": sid,
        "chat_session_id": sid,
        "user_message": str(user_message or ""),
        "assistant_message": str(assistant_message or ""),
        "tool_calls": tool_calls,
        "report_paths": report_paths,
        "metadata": metadata,
    }
    main_session_id = _extract_main_session_id(metadata)

    path = _session_path(sid)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=True)
    with _LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    context_sid = main_session_id or sid
    with audit_context(tool=str(audit_tool_name or "save_chat_exchange"), session_id=context_sid):
        write_audit_event(
            "chat.turn.saved",
            {
                "session_id": sid,
                "chat_session_id": sid,
                "mcp_session_id": main_session_id or fallback_main_sid,
                "main_session_id": main_session_id or fallback_main_sid,
                "turn_id": entry["turn_id"],
                "path": str(path),
                "report_paths": report_paths,
                "tool_call_count": len(tool_calls),
            },
        )
    return {
        "success": True,
        "session_id": sid,
        "chat_session_id": sid,
        "main_session_id": main_session_id or fallback_main_sid,
        "turn_id": entry["turn_id"],
        "path": str(path),
    }


def _load_turns(path: Path) -> list[dict]:
    if not path.exists():
        return []
    turns: list[dict] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if isinstance(row, dict):
                turns.append(row)
    turns.sort(key=lambda r: str(r.get("timestamp", "")))
    return turns


def register_chat_history_tools(mcp):
    @mcp.tool()
    async def save_chat_exchange(
        chat_session_id: str,
        user_message: str,
        assistant_message: str,
        tool_calls_json: str = "[]",
        report_paths_json: str = "[]",
        metadata_json: str = "{}",
        turn_id: str = "",
    ) -> dict:
        """Save a full chat turn for dashboard session history.

        Args:
            chat_session_id: Stable session identifier used across turns.
            user_message: Original user message text.
            assistant_message: Assistant response text.
            tool_calls_json: JSON array describing tools used this turn.
            report_paths_json: JSON array of generated report paths.
            metadata_json: JSON object for extra metadata.
            turn_id: Optional custom turn id.
        """
        return persist_chat_turn(
            chat_session_id=chat_session_id,
            user_message=user_message,
            assistant_message=assistant_message,
            tool_calls_json=tool_calls_json,
            report_paths_json=report_paths_json,
            metadata_json=metadata_json,
            turn_id=turn_id,
            audit_tool_name="save_chat_exchange",
        )

    @mcp.tool()
    async def save_binary_report_artifact(
        session_id: str,
        filename: str,
        content_base64: str,
        mime_type: str = "",
        run_directory: str = "",
        append: bool = False,
    ) -> dict:
        """Decode and persist a binary report artifact under /opt/uts-mcp/reports.

        Args:
            session_id: Main session id owning the artifact.
            filename: Report filename (.html, .pdf, .docx).
            content_base64: Base64 encoded file bytes.
            mime_type: Optional MIME hint for metadata.
            run_directory: Optional existing run folder under /opt/uts-mcp/reports.
            append: Append decoded bytes to existing file (for chunked uploads).
        """
        sid = str(session_id or "").strip()
        if not sid:
            return {"success": False, "error": "session_id is required"}
        safe_name = _safe_report_filename(filename)
        if not safe_name:
            return {"success": False, "error": "filename must end with .html, .pdf, or .docx"}

        try:
            chunk = base64.b64decode(str(content_base64 or "").encode("utf-8"), validate=True)
        except (binascii.Error, ValueError):
            return {"success": False, "error": "content_base64 is not valid base64"}

        run_dir, run_dir_err = _resolve_report_run_dir(sid, run_directory)
        if run_dir is None:
            return {"success": False, "error": run_dir_err}
        path = run_dir / safe_name
        mode = "ab" if append else "wb"
        with _LOCK:
            with path.open(mode) as handle:
                handle.write(chunk)

        size_bytes = path.stat().st_size if path.exists() else 0
        if size_bytes <= 0:
            return {"success": False, "error": f"Saved artifact is empty: {path}"}

        with audit_context(tool="save_binary_report_artifact", session_id=sid):
            write_audit_event(
                "report.binary.saved",
                {
                    "session_id": sid,
                    "mcp_session_id": sid,
                    "main_session_id": sid,
                    "path": str(path),
                    "run_directory": str(run_dir),
                    "append": bool(append),
                    "mime_type": str(mime_type or ""),
                    "size_bytes": size_bytes,
                },
            )
        return {
            "success": True,
            "session_id": sid,
            "mcp_session_id": sid,
            "main_session_id": sid,
            "path": str(path),
            "run_directory": str(run_dir),
            "size_bytes": size_bytes,
            "mime_type": str(mime_type or ""),
            "appended": bool(append),
        }

    @mcp.tool()
    async def list_saved_chat_sessions(limit: int = 200) -> dict:
        """List chat sessions persisted via save_chat_exchange."""
        base = _chat_history_dir()
        if not base.exists():
            return {"success": True, "sessions": [], "count": 0, "base_dir": str(base)}

        rows: list[dict] = []
        for file_path in sorted(base.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True):
            turns = _load_turns(file_path)
            if not turns:
                continue
            start = str(turns[0].get("timestamp", ""))
            end = str(turns[-1].get("timestamp", ""))
            session_id = str(turns[0].get("session_id") or file_path.stem)
            report_paths: set[str] = set()
            for turn in turns:
                for p in _coerce_string_list(turn.get("report_paths", [])):
                    report_paths.add(p)
            rows.append(
                {
                    "session_id": session_id,
                    "turn_count": len(turns),
                    "start": start,
                    "end": end,
                    "report_count": len(report_paths),
                    "path": str(file_path),
                }
            )
            if len(rows) >= max(1, int(limit)):
                break

        return {
            "success": True,
            "sessions": rows,
            "count": len(rows),
            "base_dir": str(base),
        }

    @mcp.tool()
    async def read_saved_chat_session(chat_session_id: str, max_turns: int = 500) -> dict:
        """Read saved chat turns for one chat_session_id."""
        sid = str(chat_session_id or "").strip()
        if not sid:
            return {"success": False, "error": "chat_session_id is required"}
        try:
            path = _session_path(sid)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

        turns = _load_turns(path)
        if max_turns > 0 and len(turns) > max_turns:
            turns = turns[-max_turns:]
        return {
            "success": True,
            "session_id": sid,
            "path": str(path),
            "turns": turns,
            "turn_count": len(turns),
        }
