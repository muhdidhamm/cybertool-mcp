"""FastAPI dashboard backend with websocket streaming and playbook APIs."""

from __future__ import annotations

import asyncio
import json
import mimetypes
import os
import threading
from pathlib import Path
from urllib.parse import parse_qs
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from tools.dashboard_server import (
    _SESSION_COOKIE_NAME,
    _SESSION_TTL_SECONDS,
    _build_dashboard_state,
    _build_session_flow_groups,
    _clear_login_failures,
    _clear_session,
    _client_ip,
    _cookie_secure_enabled,
    _dashboard_asset_path,
    _dashboard_html,
    _dashboard_username,
    _chat_history_dir,
    _is_authorized,
    _is_inline_preview,
    _is_login_locked,
    _issue_session,
    _login_auth_enabled,
    _login_html,
    _load_chat_turns,
    _normalize_chat_turn_for_display,
    _normalize_timestamp_text,
    _output_dir,
    _parse_cookie_header,
    _read_text_file,
    _record_login_failure,
    _resolve_allowed_file,
    _reports_dir,
    _validate_dashboard_assets_or_raise,
    _verify_password,
)
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
from tools.subscription import (
    get_subscription_status,
    invalidate_subscription_cache,
    subscription_license_path,
)

_STARTED = False
_LOCK = threading.Lock()
_MAX_SUBSCRIPTION_UPLOAD_BYTES = 128 * 1024


def _create_tool_registry(mcp_instance) -> dict[str, Any]:
    registry: dict[str, Any] = {}
    tool_manager = getattr(mcp_instance, "_tool_manager", None)
    if tool_manager is None:
        return registry
    for item in getattr(tool_manager, "_tools", {}).values():
        name = getattr(item, "name", "")
        fn = getattr(item, "fn", None)
        if name and fn:
            registry[name] = fn
    return registry


def _query_dict_from_request(request: Request) -> dict[str, list[str]]:
    query: dict[str, list[str]] = {}
    for key in request.query_params.keys():
        query[key] = list(request.query_params.getlist(key))
    return query


def _query_dict_from_websocket(websocket: WebSocket) -> dict[str, list[str]]:
    query: dict[str, list[str]] = {}
    for key in websocket.query_params.keys():
        query[key] = list(websocket.query_params.getlist(key))
    return query


def _unauthorized_json() -> JSONResponse:
    return JSONResponse(
        {"success": False, "error": "Unauthorized dashboard access"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


def create_dashboard_app(mcp_instance) -> FastAPI:
    app = FastAPI(title="Unified ThreatLens Dashboard API", version="1.0.0")
    ensure_playbook_store()

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        path = request.url.path
        query = _query_dict_from_request(request)
        if path == "/login":
            return await call_next(request)
        if path == "/logout":
            return await call_next(request)
        if not _is_authorized(request.headers, query):
            if path.startswith("/api/"):
                return _unauthorized_json()
            if _login_auth_enabled():
                return RedirectResponse(url="/login", status_code=302)
            return _unauthorized_json()
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return _dashboard_html()

    @app.get("/assets/{asset_name}")
    async def static_asset(asset_name: str):
        try:
            asset_path = _dashboard_asset_path(asset_name)
        except Exception as exc:
            raise HTTPException(status_code=404, detail="Not found") from exc
        if not asset_path.exists() or not asset_path.is_file():
            raise HTTPException(status_code=404, detail="Not found")
        content_type, _ = mimetypes.guess_type(str(asset_path))
        return Response(
            content=asset_path.read_bytes(),
            media_type=content_type or "application/octet-stream",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        if not _login_auth_enabled():
            return RedirectResponse(url="/", status_code=302)
        if _is_authorized(request.headers, _query_dict_from_request(request)):
            return RedirectResponse(url="/", status_code=302)
        return HTMLResponse(_login_html(subscription_status=get_subscription_status()), status_code=200)

    @app.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request) -> Response:
        if not _login_auth_enabled():
            return JSONResponse({"success": False, "error": "Login auth is not enabled"}, status_code=400)

        client_ip = _client_ip(request.headers, request.client)
        locked, remaining = _is_login_locked(client_ip)
        if locked:
            return HTMLResponse(
                _login_html(
                    f"Too many failed attempts. Try again in {remaining} seconds.",
                    subscription_status=get_subscription_status(),
                ),
                status_code=429,
            )

        body = (await request.body()).decode("utf-8", errors="replace")
        form = parse_qs(body)
        username = str((form.get("username") or [""])[0]).strip()
        password = str((form.get("password") or [""])[0]).strip()
        if username != _dashboard_username() or not _verify_password(password):
            locked_now, lockout_seconds = _record_login_failure(client_ip)
            if locked_now:
                return HTMLResponse(
                    _login_html(
                        f"Too many failed attempts. Account locked for {lockout_seconds} seconds.",
                        subscription_status=get_subscription_status(),
                    ),
                    status_code=429,
                )
            return HTMLResponse(
                _login_html("Invalid username or password", subscription_status=get_subscription_status()),
                status_code=401,
            )

        _clear_login_failures(client_ip)
        sid, _ = _issue_session()
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key=_SESSION_COOKIE_NAME,
            value=sid,
            max_age=_SESSION_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=_cookie_secure_enabled(),
            path="/",
        )
        return response

    @app.get("/logout")
    async def logout(request: Request) -> Response:
        cookies = _parse_cookie_header(request.headers.get("Cookie", ""))
        sid = cookies.get(_SESSION_COOKIE_NAME, "")
        if sid:
            _clear_session(sid)
        response = RedirectResponse(url="/login", status_code=302)
        response.delete_cookie(_SESSION_COOKIE_NAME, path="/")
        return response

    @app.get("/api/sessions")
    async def sessions() -> dict[str, Any]:
        state = _build_dashboard_state()
        return {
            "generated_at": state["generated_at"],
            "audit_log_path": state["audit_log_path"],
            "sessions": state["sessions"],
        }

    @app.get("/api/sessions/{session_id}")
    async def session_detail(session_id: str) -> dict[str, Any]:
        state = _build_dashboard_state()
        detail = state["session_details"].get(session_id)
        if not detail:
            raise HTTPException(status_code=404, detail=f"Unknown session: {session_id}")
        flow_groups = _build_session_flow_groups(detail.get("events", []))
        return {
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
        }

    @app.get("/api/reports")
    async def reports() -> dict[str, Any]:
        return {"success": True, "reports": _build_dashboard_state()["reports"]}

    @app.get("/api/output-files")
    async def output_files() -> dict[str, Any]:
        return {"success": True, "files": _build_dashboard_state()["output_files"]}

    @app.get("/api/subscription/status")
    async def subscription_status() -> dict[str, Any]:
        return {"success": True, "subscription": get_subscription_status()}

    @app.post("/api/subscription/upload")
    async def subscription_upload(request: Request) -> dict[str, Any]:
        filename = str(request.headers.get("X-Subscription-Filename", "subscription.lic")).strip() or "subscription.lic"
        if not filename.lower().endswith(".lic"):
            raise HTTPException(status_code=400, detail="Uploaded file must use .lic extension")
        data = await request.body()
        if not data:
            raise HTTPException(status_code=400, detail="Upload body is empty")
        if len(data) > _MAX_SUBSCRIPTION_UPLOAD_BYTES:
            raise HTTPException(status_code=400, detail="Subscription file exceeds 128KB limit")

        target = subscription_license_path()
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            temp_path = target.with_suffix(f"{target.suffix}.tmp")
            temp_path.write_bytes(data)
            temp_path.replace(target)
            invalidate_subscription_cache()
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"Failed to store subscription file: {exc}") from exc
        return {"success": True, "subscription": get_subscription_status(force_refresh=True), "path": str(target)}

    @app.get("/api/playbooks")
    async def playbooks() -> dict[str, Any]:
        return {"success": True, "playbooks": list_playbooks(), "playbooks_dir": os.environ.get("MCP_PLAYBOOKS_DIR", "/opt/uts-mcp/data/playbooks")}

    @app.get("/api/playbooks/{name}")
    async def playbook_detail(name: str) -> dict[str, Any]:
        try:
            return {"success": True, **get_playbook(name)}
        except Exception as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.post("/api/playbooks")
    async def playbook_create(payload: dict[str, Any]) -> dict[str, Any]:
        name = str(payload.get("name", "")).strip()
        content = str(payload.get("content", ""))
        expected_version = payload.get("expected_version")
        expected = int(expected_version) if expected_version is not None else None
        return create_or_update_playbook(name, content, expected_version=expected)

    @app.put("/api/playbooks/{name}")
    async def playbook_update(name: str, payload: dict[str, Any]) -> dict[str, Any]:
        content = str(payload.get("content", ""))
        expected_version = payload.get("expected_version")
        expected = int(expected_version) if expected_version is not None else None
        return create_or_update_playbook(name, content, expected_version=expected)

    @app.delete("/api/playbooks/{name}")
    async def playbook_delete(name: str, soft_delete: bool = Query(True)) -> dict[str, Any]:
        return delete_playbook(name, soft_delete=soft_delete)

    @app.post("/api/playbooks/{name}/clone")
    async def playbook_clone(name: str, payload: dict[str, Any]) -> dict[str, Any]:
        target_name = str(payload.get("target_name", "")).strip()
        return clone_playbook(name, target_name)

    @app.post("/api/playbooks/{name}/validate")
    async def playbook_validate(name: str, payload: dict[str, Any]) -> dict[str, Any]:
        content = str(payload.get("content", ""))
        result = validate_playbook_yaml(content)
        return {"success": True, "name": name, **result}

    @app.post("/api/playbooks/{name}/run")
    async def playbook_run(name: str, payload: dict[str, Any]) -> dict[str, Any]:
        target = str(payload.get("target", "")).strip()
        if not target:
            raise HTTPException(status_code=400, detail="target is required")
        variables = payload.get("variables", {})
        if variables is None:
            variables = {}
        if not isinstance(variables, dict):
            raise HTTPException(status_code=400, detail="variables must be an object")
        return {
            "success": True,
            "run": await run_playbook_runtime(
                name,
                target,
                _create_tool_registry(mcp_instance),
                variables=variables,
            ),
        }

    @app.get("/api/playbooks/{name}/runs")
    async def playbook_runs(name: str, limit: int = Query(default=50, ge=1, le=500)) -> dict[str, Any]:
        return {"success": True, "runs": list_playbook_runs(name, limit=limit)}

    @app.get("/api/file")
    async def read_file(path: str) -> dict[str, Any]:
        result = _read_text_file(path, allowed_bases=[_reports_dir(), _output_dir(), Path("/opt/uts-mcp/logs"), _chat_history_dir()])
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "failed"))
        return result

    @app.get("/file/view")
    async def file_view(path: str):
        allowed_bases = [_reports_dir(), _output_dir(), Path("/opt/uts-mcp/logs")]
        ok, resolved, error = _resolve_allowed_file(path, allowed_bases)
        if not ok or resolved is None:
            raise HTTPException(status_code=400, detail=error)

        data = resolved.read_bytes()
        content_type, _ = mimetypes.guess_type(str(resolved))
        content_type = content_type or "application/octet-stream"
        disposition = "inline" if _is_inline_preview(content_type, resolved) else "attachment"
        return Response(
            content=data,
            media_type=content_type,
            headers={
                "X-Content-Type-Options": "nosniff",
                "Content-Disposition": f'{disposition}; filename="{resolved.name}"',
            },
        )

    @app.websocket("/ws/events")
    async def ws_events(websocket: WebSocket):
        if not _is_authorized(websocket.headers, _query_dict_from_websocket(websocket)):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        audit_path = Path(os.environ.get("MCP_AUDIT_LOG_PATH", "/opt/uts-mcp/logs/mcp_audit.jsonl"))
        offset = 0
        try:
            while True:
                if audit_path.exists():
                    data = audit_path.read_text(encoding="utf-8", errors="replace")
                    if len(data) > offset:
                        chunk = data[offset:]
                        for line in chunk.splitlines():
                            raw = line.strip()
                            if not raw:
                                continue
                            try:
                                payload = json.loads(raw)
                            except Exception:
                                continue
                            await websocket.send_json(payload)
                        offset = len(data)
                await asyncio.sleep(1.0)
        except WebSocketDisconnect:
            return

    return app


def start_fastapi_dashboard_server(mcp_instance) -> None:
    global _STARTED
    with _LOCK:
        if _STARTED:
            return
        _STARTED = True

    _validate_dashboard_assets_or_raise()

    host = os.environ.get("MCP_DASHBOARD_HOST", "0.0.0.0").strip() or "0.0.0.0"
    raw_port = os.environ.get("MCP_DASHBOARD_PORT", "8090").strip()
    try:
        port = int(raw_port)
    except ValueError:
        port = 8090

    app = create_dashboard_app(mcp_instance)
    config = uvicorn.Config(app=app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config=config)
    thread = threading.Thread(target=server.run, name="mcp-dashboard-fastapi", daemon=True)
    thread.start()
