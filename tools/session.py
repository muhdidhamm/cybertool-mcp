"""Session boundary tools.

Claude Desktop does not reliably signal "new user turn" boundaries to the MCP server.
This tool lets the client explicitly declare a new session and provides a stable
session id to group subsequent audit events.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from tools.audit_logger import write_audit_event
from tools.chat_history import persist_chat_turn
from tools.session_finalize import finalize_session_reports
from tools.session_manager import (
    clear_active_session_id,
    coerce_session_id,
    get_active_session_id,
    set_active_session_id,
)

_PROCESS_START_MONO = time.monotonic()


def register_session_tools(mcp) -> None:
    @mcp.tool()
    async def mcp_health_check(nonce: str = "") -> dict:
        """Fast health probe for MCP transport/bridge diagnostics."""
        active_sid = get_active_session_id()
        return {
            "success": True,
            "server_timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": round(time.monotonic() - _PROCESS_START_MONO, 3),
            "nonce": str(nonce or ""),
            "active_session_id": active_sid,
        }

    @mcp.tool()
    async def start_session(
        chat_session_id: str = "",
        session_id: str = "",
        label: str = "",
        source: str = "explicit_tool",
    ) -> dict:
        """Start a new audit session and make it active for subsequent tool calls.

        Args:
            chat_session_id: Optional stable chat session identifier (recommended).
            session_id: Optional explicit session id. If empty, a UUID is generated.
            label: Optional human-friendly label (e.g. the user request summary).
            source: Session creation source. Defaults to 'explicit_tool'.
        """

        requested_sid = coerce_session_id(session_id)
        active_sid = get_active_session_id()
        sid = requested_sid or str(uuid.uuid4())
        reused = bool(requested_sid and requested_sid == active_sid)
        set_active_session_id(sid)
        write_audit_event(
            "session.start",
            {
                "session_id": sid,
                "mcp_session_id": sid,
                "main_session_id": sid,
                "reused": reused,
                "chat_session_id": str(chat_session_id or "").strip(),
                "label": str(label or "").strip(),
                "source": str(source or "explicit_tool").strip(),
            },
        )
        return {"success": True, "session_id": sid, "reused": reused}

    @mcp.tool()
    async def end_session(
        session_id: str = "",
        source: str = "explicit_tool",
        chat_session_id: str = "",
        user_message: str = "",
        assistant_message: str = "",
        tool_calls_json: str = "[]",
        report_paths_json: str = "[]",
        metadata_json: str = "{}",
        turn_id: str = "",
    ) -> dict:
        """End the current session (purely for audit and to clear active session)."""
        requested_sid = coerce_session_id(session_id)
        active_sid = get_active_session_id()
        sid = requested_sid or active_sid
        ended = bool(active_sid and (not requested_sid or requested_sid == active_sid))
        chat_sid = str(chat_session_id or "").strip()
        warnings: list[str] = []
        chat_saved = False
        chat_save_result: dict | None = None
        has_user = bool(str(user_message or "").strip())
        has_assistant = bool(str(assistant_message or "").strip())

        inline_chat_sid = chat_sid or str(sid or "").strip()
        if has_user and has_assistant and inline_chat_sid:
            chat_save_result = persist_chat_turn(
                chat_session_id=inline_chat_sid,
                user_message=user_message,
                assistant_message=assistant_message,
                tool_calls_json=tool_calls_json,
                report_paths_json=report_paths_json,
                metadata_json=metadata_json,
                turn_id=turn_id,
                default_main_session_id=str(sid or ""),
                audit_tool_name="end_session",
            )
            chat_saved = bool(chat_save_result.get("success"))
            if not chat_saved:
                warnings.append("inline_chat_capture_failed")
                write_audit_event(
                    "session.chat_capture.failed",
                    {
                        "session_id": sid,
                        "mcp_session_id": sid,
                        "main_session_id": sid,
                        "chat_session_id": inline_chat_sid,
                        "error": str(chat_save_result.get("error", "chat persistence failed")),
                    },
                )
            else:
                write_audit_event(
                    "session.chat_capture.saved",
                    {
                        "session_id": sid,
                        "mcp_session_id": sid,
                        "main_session_id": sid,
                        "chat_session_id": inline_chat_sid,
                        "turn_id": str(chat_save_result.get("turn_id", "")),
                        "path": str(chat_save_result.get("path", "")),
                    },
                )
        else:
            reason = "missing_payload"
            if not inline_chat_sid:
                reason = "missing_chat_session_id"
            warnings.append(f"inline_chat_capture_skipped:{reason}")
            write_audit_event(
                "session.chat_capture.skipped",
                {
                    "session_id": sid,
                    "mcp_session_id": sid,
                    "main_session_id": sid,
                    "chat_session_id": chat_sid,
                    "reason": reason,
                    "has_user_message": has_user,
                    "has_assistant_message": has_assistant,
                },
            )

        finalize_summary = {
            "success": False,
            "session_id": sid,
            "chat_session_ids": [chat_sid] if chat_sid else [],
            "run_directory": "",
            "copied": [],
            "skipped_missing": [],
            "skipped_empty": [],
            "source_count": 0,
            "resolved": [],
        }
        finalized = False
        if sid:
            write_audit_event(
                "session.finalize.start",
                {
                    "session_id": sid,
                    "mcp_session_id": sid,
                    "main_session_id": sid,
                    "chat_session_id": chat_sid,
                    "source": str(source or "explicit_tool").strip(),
                },
            )
            finalize_summary = finalize_session_reports(sid, [chat_sid] if chat_sid else None)
            finalized = bool(finalize_summary.get("success"))
            write_audit_event(
                "session.finalize.result",
                {
                    "session_id": sid,
                    "mcp_session_id": sid,
                    "main_session_id": sid,
                    "chat_session_id": chat_sid,
                    "finalized": finalized,
                    "run_directory": str(finalize_summary.get("run_directory", "")),
                    "copied_count": len(finalize_summary.get("copied", [])),
                    "skipped_missing_count": len(finalize_summary.get("skipped_missing", [])),
                    "skipped_empty_count": len(finalize_summary.get("skipped_empty", [])),
                },
            )
        write_audit_event(
            "session.end",
            {
                "session_id": sid,
                "mcp_session_id": sid,
                "main_session_id": sid,
                "chat_session_id": chat_sid,
                "ended": ended,
                "finalized": finalized,
                "active_session_id": active_sid,
                "source": str(source or "explicit_tool").strip(),
            },
        )
        if ended:
            clear_active_session_id()
        return {
            "success": True,
            "ended": ended,
            "finalized": finalized,
            "chat_saved": chat_saved,
            "chat_save_result": chat_save_result,
            "warnings": warnings,
            "session_id": sid,
            "finalize_summary": finalize_summary,
        }

