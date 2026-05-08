"""In-process session state for audit grouping.

This module maintains a current "active" session id that can be reused across
multiple tool calls so audit events can be grouped into a single session.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any


_ACTIVE_SESSION_ID: ContextVar[str] = ContextVar("uts_active_session_id", default="")


def get_active_session_id() -> str:
    return str(_ACTIVE_SESSION_ID.get() or "").strip()


def set_active_session_id(session_id: str) -> str:
    sid = str(session_id or "").strip()
    _ACTIVE_SESSION_ID.set(sid)
    return sid


def clear_active_session_id() -> None:
    _ACTIVE_SESSION_ID.set("")


def coerce_session_id(value: Any) -> str:
    """Best-effort conversion of a caller-provided value to a session id string."""
    if value is None:
        return ""
    sid = str(value).strip()
    return sid

