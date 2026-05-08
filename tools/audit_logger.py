"""Audit logging helpers for MCP tool and command execution."""

from __future__ import annotations

import json
import os
import sys
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any
from tools.time_utils import iso_now_tz

_LOCK = threading.Lock()
_SENSITIVE_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "auth",
    "authorization",
    "cookie",
    "private_key",
    "ssh_key",
)
_SESSION_KEYS = (
    "mcp_session_id",
    "main_session_id",
    "session_id",
    "chat_session_id",
    "conversation_id",
    "thread_id",
)

_CURRENT_TOOL: ContextVar[str] = ContextVar("mcp_audit_tool", default="")
_CURRENT_SESSION_ID: ContextVar[str] = ContextVar("mcp_audit_session_id", default="")
_CURRENT_INVOCATION_ID: ContextVar[str] = ContextVar("mcp_audit_invocation_id", default="")
_WRITE_FAILURE_COUNT = 0


def _is_enabled() -> bool:
    value = os.environ.get("MCP_AUDIT_LOG_ENABLED", "true").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _max_field_chars() -> int:
    raw = os.environ.get("MCP_AUDIT_MAX_FIELD_CHARS", "4000").strip()
    try:
        return max(256, int(raw))
    except ValueError:
        return 4000


def _audit_log_path() -> Path:
    raw = os.environ.get("MCP_AUDIT_LOG_PATH", "/opt/uts-mcp/logs/mcp_audit.jsonl").strip()
    return Path(raw or "/opt/uts-mcp/logs/mcp_audit.jsonl")


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"... [truncated {len(value) - limit} chars]"


def _key_is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_MARKERS)


def _sanitize_value(value: Any, limit: int, key_hint: str = "") -> Any:
    if key_hint and _key_is_sensitive(key_hint):
        return "[REDACTED]"

    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return _truncate(value, limit)

    if isinstance(value, bytes):
        decoded = value.decode("utf-8", errors="replace")
        return _truncate(decoded, limit)

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            sanitized[key_str] = _sanitize_value(item, limit, key_str)
        return sanitized

    if isinstance(value, (list, tuple, set)):
        return [_sanitize_value(item, limit) for item in value]

    return _truncate(str(value), limit)


def extract_session_id(value: Any) -> str:
    """Extract a stable session id from call args if present."""
    if isinstance(value, dict):
        for key in _SESSION_KEYS:
            candidate = value.get(key)
            if candidate is not None and str(candidate).strip():
                return str(candidate).strip()
        nested_args = value.get("args")
        if isinstance(nested_args, dict):
            return extract_session_id(nested_args)
    return ""


def get_audit_context() -> dict[str, str]:
    """Return currently active tool/session identifiers."""
    return {
        "tool": _CURRENT_TOOL.get(),
        "session_id": _CURRENT_SESSION_ID.get(),
        "invocation_id": _CURRENT_INVOCATION_ID.get(),
    }


@contextmanager
def audit_context(tool: str = "", session_id: str = "", invocation_id: str = ""):
    """Set contextual identifiers used by nested audit events."""
    tool_token = _CURRENT_TOOL.set(str(tool or "").strip())
    session_token = _CURRENT_SESSION_ID.set(str(session_id or "").strip())
    invocation_token = _CURRENT_INVOCATION_ID.set(str(invocation_id or "").strip())
    try:
        yield
    finally:
        _CURRENT_TOOL.reset(tool_token)
        _CURRENT_SESSION_ID.reset(session_token)
        _CURRENT_INVOCATION_ID.reset(invocation_token)


def write_audit_event(event_type: str, payload: dict[str, Any]) -> None:
    """Write a structured JSONL audit event."""
    if not _is_enabled():
        return

    limit = _max_field_chars()
    context = get_audit_context()
    payload_with_context = dict(payload)
    if context["tool"] and "tool" not in payload_with_context:
        payload_with_context["tool"] = context["tool"]
    if context["session_id"] and "session_id" not in payload_with_context:
        payload_with_context["session_id"] = context["session_id"]
    if context["session_id"] and "mcp_session_id" not in payload_with_context:
        payload_with_context["mcp_session_id"] = context["session_id"]
    if context["session_id"] and "main_session_id" not in payload_with_context:
        payload_with_context["main_session_id"] = context["session_id"]
    if context["invocation_id"] and "invocation_id" not in payload_with_context:
        payload_with_context["invocation_id"] = context["invocation_id"]

    safe_payload = _sanitize_value(payload_with_context, limit)
    event = {
        "timestamp": iso_now_tz(),
        "event_type": event_type,
        "payload": safe_payload,
    }

    line = json.dumps(event, ensure_ascii=True)
    target = _audit_log_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK:
            with target.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except Exception as exc:
        global _WRITE_FAILURE_COUNT
        _WRITE_FAILURE_COUNT += 1
        try:
            sys.stderr.write(
                f"[audit_logger] write failure #{_WRITE_FAILURE_COUNT}: {type(exc).__name__}: {exc}\n"
            )
        except Exception:
            pass
