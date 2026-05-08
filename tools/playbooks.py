"""Playbook schema, persistence, and execution runtime."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from tools.audit_logger import write_audit_event
from tools.contracts import (
    PlaybookDefinition,
    PlaybookRunResult,
    PlaybookRunStepResult,
    PlaybookValidationResult,
)

_DEFAULT_PLAYBOOKS_DIR = "/opt/uts-mcp/data/playbooks"
_RUN_HISTORY_FILE = "run_history.jsonl"
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DEFAULT_EXAMPLES_DIR = "/opt/uts-mcp/examples/playbooks"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _playbooks_dir() -> Path:
    raw = os.environ.get("MCP_PLAYBOOKS_DIR", _DEFAULT_PLAYBOOKS_DIR).strip()
    return Path(raw or _DEFAULT_PLAYBOOKS_DIR)


def _run_history_path() -> Path:
    return _playbooks_dir() / _RUN_HISTORY_FILE


def _safe_name(name: str) -> str:
    cleaned = str(name or "").strip()
    if not _SAFE_NAME_RE.match(cleaned):
        raise ValueError("Invalid playbook name. Use letters, numbers, dot, dash, underscore.")
    return cleaned


def _playbook_path(name: str) -> Path:
    safe = _safe_name(name)
    target = (_playbooks_dir() / f"{safe}.yaml").resolve()
    base = _playbooks_dir().resolve()
    try:
        target.relative_to(base)
    except Exception as exc:
        raise ValueError("Invalid playbook path") from exc
    return target


def ensure_playbook_store() -> Path:
    store = _playbooks_dir()
    store.mkdir(parents=True, exist_ok=True)
    _seed_example_playbooks(store)
    return store


def _examples_playbooks_dir() -> Path:
    raw = os.environ.get("MCP_PLAYBOOKS_EXAMPLES_DIR", _DEFAULT_EXAMPLES_DIR).strip()
    configured = Path(raw or _DEFAULT_EXAMPLES_DIR)
    if configured.exists():
        return configured
    # Local dev fallback when running directly from repo.
    return Path(__file__).resolve().parents[1] / "examples" / "playbooks"


def _seed_example_playbooks(store: Path) -> None:
    examples_dir = _examples_playbooks_dir()
    if not examples_dir.exists() or not examples_dir.is_dir():
        return
    for src in sorted(examples_dir.glob("*.yaml")):
        if not src.is_file():
            continue
        dst = store / src.name
        if dst.exists():
            continue
        try:
            # Validate before seeding into persistent store.
            parsed = _parse_playbook(src.read_text(encoding="utf-8"))
            if not parsed.valid:
                continue
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
            write_audit_event(
                "playbook.seed",
                {
                    "name": src.stem,
                    "source_path": str(src),
                    "target_path": str(dst),
                },
            )
        except Exception:
            continue


def _parse_playbook(text: str) -> PlaybookValidationResult:
    try:
        raw = yaml.safe_load(text) or {}
    except Exception as exc:
        return PlaybookValidationResult(valid=False, errors=[f"YAML parse error: {exc}"])
    try:
        parsed = PlaybookDefinition.model_validate(raw)
    except Exception as exc:
        return PlaybookValidationResult(valid=False, errors=[str(exc)])

    errors: list[str] = []
    step_ids: set[str] = set()
    for step in parsed.steps:
        if step.id in step_ids:
            errors.append(f"Duplicate step id: {step.id}")
        step_ids.add(step.id)
    for step in parsed.steps:
        for dep in step.depends_on:
            if dep not in step_ids:
                errors.append(f"Unknown dependency '{dep}' in step '{step.id}'")
    return PlaybookValidationResult(valid=not errors, errors=errors, normalized=parsed)


def validate_playbook_yaml(content: str) -> dict[str, Any]:
    result = _parse_playbook(content)
    payload = result.model_dump()
    if payload.get("normalized"):
        payload["normalized"] = result.normalized.model_dump() if result.normalized else None
    return payload


def list_playbooks() -> list[dict[str, Any]]:
    ensure_playbook_store()
    rows: list[dict[str, Any]] = []
    for path in sorted(_playbooks_dir().glob("*.yaml")):
        try:
            text = path.read_text(encoding="utf-8")
            parsed = _parse_playbook(text)
            md = parsed.normalized.metadata if parsed.normalized else None
            rows.append(
                {
                    "name": path.stem,
                    "path": str(path),
                    "valid": parsed.valid,
                    "errors": parsed.errors,
                    "tags": list(md.tags) if md else [],
                    "owner": md.owner if md else "",
                    "source": md.source if md else "",
                    "updated_at": md.updated_at if md else "",
                    "version": md.version if md else 0,
                }
            )
        except Exception as exc:
            rows.append({"name": path.stem, "path": str(path), "valid": False, "errors": [str(exc)]})
    rows.sort(key=lambda r: str(r.get("name", "")))
    return rows


def get_playbook(name: str) -> dict[str, Any]:
    ensure_playbook_store()
    path = _playbook_path(name)
    if not path.exists():
        raise FileNotFoundError(f"Playbook not found: {name}")
    text = path.read_text(encoding="utf-8")
    parsed = _parse_playbook(text)
    return {
        "name": name,
        "path": str(path),
        "yaml": text,
        "parsed": parsed.normalized.model_dump() if parsed.normalized else None,
        "valid": parsed.valid,
        "errors": parsed.errors,
    }


def create_or_update_playbook(name: str, content: str, expected_version: int | None = None) -> dict[str, Any]:
    ensure_playbook_store()
    safe_name = _safe_name(name)
    path = _playbook_path(safe_name)
    validation = _parse_playbook(content)
    if not validation.valid or not validation.normalized:
        return {"success": False, "error": "Invalid playbook content", "validation": validation.model_dump()}

    model = validation.normalized
    existing_version = 0
    if path.exists():
        current = _parse_playbook(path.read_text(encoding="utf-8"))
        if current.normalized:
            existing_version = int(current.normalized.metadata.version)
    if expected_version is not None and expected_version != existing_version:
        return {
            "success": False,
            "error": "Version conflict",
            "expected_version": expected_version,
            "current_version": existing_version,
        }

    model.metadata.name = safe_name
    model.metadata.updated_at = _now_iso()
    model.metadata.version = existing_version + 1
    dumped = yaml.safe_dump(model.model_dump(), sort_keys=False)
    path.write_text(dumped, encoding="utf-8")
    action = "update" if existing_version else "create"
    write_audit_event(f"playbook.{action}", {"name": safe_name, "path": str(path), "version": model.metadata.version})
    return {
        "success": True,
        "name": safe_name,
        "path": str(path),
        "version": model.metadata.version,
        "validation": validation.model_dump(),
    }


def delete_playbook(name: str, soft_delete: bool = True) -> dict[str, Any]:
    ensure_playbook_store()
    path = _playbook_path(name)
    if not path.exists():
        return {"success": False, "error": f"Playbook not found: {name}"}
    if soft_delete:
        trash_dir = _playbooks_dir() / ".trash"
        trash_dir.mkdir(parents=True, exist_ok=True)
        dst = trash_dir / f"{path.stem}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.yaml"
        path.rename(dst)
        write_audit_event("playbook.delete", {"name": name, "path": str(path), "soft_delete": True, "trashed_to": str(dst)})
        return {"success": True, "name": name, "soft_delete": True, "trashed_to": str(dst)}
    path.unlink()
    write_audit_event("playbook.delete", {"name": name, "path": str(path), "soft_delete": False})
    return {"success": True, "name": name, "soft_delete": False}


def clone_playbook(source_name: str, target_name: str) -> dict[str, Any]:
    source = get_playbook(source_name)
    raw = source.get("yaml", "")
    validation = _parse_playbook(raw)
    if not validation.normalized:
        return {"success": False, "error": "Source playbook is invalid"}
    model = validation.normalized
    model.metadata.name = _safe_name(target_name)
    model.metadata.source = "clone"
    model.metadata.updated_at = _now_iso()
    model.metadata.version = 1
    dumped = yaml.safe_dump(model.model_dump(), sort_keys=False)
    result = create_or_update_playbook(target_name, dumped)
    if result.get("success"):
        write_audit_event("playbook.clone", {"source": source_name, "target": target_name})
    return result


def _render_template_value(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        rendered = value
        for key, replacement in context.items():
            rendered = rendered.replace(f"{{{{{key}}}}}", replacement)
        return rendered
    if isinstance(value, dict):
        return {k: _render_template_value(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_template_value(v, context) for v in value]
    return value


def _resolve_args(args: dict[str, Any], target: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    context: dict[str, str] = {"target": str(target)}
    for key, value in (variables or {}).items():
        context[str(key)] = str(value)
    return _render_template_value(dict(args or {}), context)


def _read_run_history(limit: int = 200) -> list[dict[str, Any]]:
    history_path = _run_history_path()
    if not history_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with history_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            try:
                rows.append(json.loads(raw))
            except Exception:
                continue
    if len(rows) > limit:
        rows = rows[-limit:]
    rows.reverse()
    return rows


def list_playbook_runs(playbook_name: str = "", limit: int = 50) -> list[dict[str, Any]]:
    rows = _read_run_history(limit=max(50, limit))
    if playbook_name:
        rows = [row for row in rows if str(row.get("playbook", "")) == playbook_name]
    return rows[:limit]


def _append_run_history(result: PlaybookRunResult) -> None:
    history_path = _run_history_path()
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with history_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result.model_dump(), ensure_ascii=True) + "\n")


async def run_playbook_runtime(
    name: str,
    target: str,
    tool_registry: dict[str, Any],
    variables: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = get_playbook(name)
    parsed = data.get("parsed") or {}
    model = PlaybookDefinition.model_validate(parsed)
    steps = model.steps

    completed: dict[str, PlaybookRunStepResult] = {}
    run_steps: list[PlaybookRunStepResult] = []
    run_id = uuid.uuid4().hex
    started_at = _now_iso()
    write_audit_event(
        "playbook.run.start",
        {
            "run_id": run_id,
            "name": name,
            "target": target,
            "variable_keys": sorted([str(k) for k in (variables or {}).keys()]),
        },
    )

    for step in steps:
        unmet = [dep for dep in step.depends_on if dep not in completed or not completed[dep].success]
        if unmet:
            failed_step = PlaybookRunStepResult(
                step_id=step.id,
                tool=step.tool,
                success=False,
                elapsed_seconds=0.0,
                output={},
                error=f"Dependencies not met: {', '.join(unmet)}",
            )
            run_steps.append(failed_step)
            completed[step.id] = failed_step
            if step.on_failure == "stop":
                break
            continue

        tool = tool_registry.get(step.tool)
        if tool is None:
            failed_step = PlaybookRunStepResult(
                step_id=step.id,
                tool=step.tool,
                success=False,
                error=f"Tool not found: {step.tool}",
            )
            run_steps.append(failed_step)
            completed[step.id] = failed_step
            if step.on_failure == "stop":
                break
            continue

        attempts = max(0, int(step.retries)) + 1
        args = _resolve_args(step.args, target, variables=variables)
        final_error = ""
        output: dict[str, Any] = {}
        success = False
        elapsed = 0.0

        for _attempt in range(attempts):
            begin = datetime.now(timezone.utc)
            try:
                if inspect.iscoroutinefunction(tool):
                    output = await asyncio.wait_for(tool(**args), timeout=max(1, step.timeout_seconds))
                else:
                    output = tool(**args)
                success = bool(output.get("success", True)) if isinstance(output, dict) else True
                elapsed = round((datetime.now(timezone.utc) - begin).total_seconds(), 3)
                if success:
                    break
                final_error = str(output.get("error", "Step returned unsuccessful status")) if isinstance(output, dict) else "Step failed"
            except Exception as exc:
                elapsed = round((datetime.now(timezone.utc) - begin).total_seconds(), 3)
                final_error = str(exc)

        step_result = PlaybookRunStepResult(
            step_id=step.id,
            tool=step.tool,
            success=success,
            elapsed_seconds=elapsed,
            output=output if isinstance(output, dict) else {"raw": str(output)},
            error=final_error,
        )
        run_steps.append(step_result)
        completed[step.id] = step_result
        write_audit_event(
            "playbook.run.step",
            {
                "run_id": run_id,
                "name": name,
                "step_id": step.id,
                "tool": step.tool,
                "success": success,
                "elapsed_seconds": elapsed,
                "error": final_error,
            },
        )
        if not success and step.on_failure == "stop":
            break

    status = "success"
    if any(not step.success for step in run_steps):
        status = "failed" if all(not step.success for step in run_steps) else "partial"
    ended_at = _now_iso()
    artifacts: list[str] = []
    for step in run_steps:
        if isinstance(step.output, dict):
            for key in ("path", "report_file"):
                value = str(step.output.get(key, "")).strip()
                if value:
                    artifacts.append(value)
            for row in step.output.get("report_paths", []) if isinstance(step.output.get("report_paths"), list) else []:
                text = str(row).strip()
                if text:
                    artifacts.append(text)
    artifacts = sorted(set(artifacts))

    result = PlaybookRunResult(
        run_id=run_id,
        playbook=name,
        target=target,
        status=status,
        started_at=started_at,
        ended_at=ended_at,
        steps=run_steps,
        artifacts=artifacts,
    )
    _append_run_history(result)
    write_audit_event(
        "playbook.run.end",
        {
            "run_id": run_id,
            "name": name,
            "target": target,
            "status": status,
            "artifact_count": len(artifacts),
        },
    )
    return result.model_dump()


def register_playbook_tools(mcp) -> None:
    ensure_playbook_store()

    async def _build_tool_registry() -> dict[str, Any]:
        registry: dict[str, Any] = {}
        try:
            tools = await mcp.list_tools(run_middleware=False)
        except Exception:
            tools = []
        for item in tools:
            name = str(getattr(item, "name", "")).strip()
            if not name:
                continue
            fn = getattr(item, "fn", None)
            if callable(fn):
                registry[name] = fn
                continue
            try:
                fetched = await mcp.get_tool(name)
            except Exception:
                fetched = None
            fetched_fn = getattr(fetched, "fn", None) if fetched is not None else None
            if callable(fetched_fn):
                registry[name] = fetched_fn
        return registry

    @mcp.tool()
    async def list_playbooks_tool() -> dict[str, Any]:
        """List persisted playbooks with validation metadata."""
        return {"success": True, "playbooks": list_playbooks(), "playbooks_dir": str(_playbooks_dir())}

    @mcp.tool()
    async def get_playbook_tool(name: str) -> dict[str, Any]:
        """Load a single playbook YAML and parsed model."""
        try:
            return {"success": True, **get_playbook(name)}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    @mcp.tool()
    async def upsert_playbook_tool(name: str, content: str, expected_version: int = -1) -> dict[str, Any]:
        """Create or update a playbook YAML with schema validation and optimistic locking."""
        exp = None if int(expected_version) < 0 else int(expected_version)
        return create_or_update_playbook(name, content, expected_version=exp)

    @mcp.tool()
    async def delete_playbook_tool(name: str, soft_delete: bool = True) -> dict[str, Any]:
        """Delete a playbook (soft-delete by default)."""
        return delete_playbook(name, soft_delete=soft_delete)

    @mcp.tool()
    async def clone_playbook_tool(source_name: str, target_name: str) -> dict[str, Any]:
        """Clone an existing playbook to a new name."""
        return clone_playbook(source_name, target_name)

    @mcp.tool()
    async def validate_playbook_tool(content: str) -> dict[str, Any]:
        """Validate YAML playbook schema and dependency graph."""
        return {"success": True, **validate_playbook_yaml(content)}

    @mcp.tool()
    async def run_playbook(name: str, target: str, variables_json: str = "") -> dict[str, Any]:
        """Run playbook with dependency-aware execution and per-step audit trails.

        Args:
            name: Playbook name.
            target: Primary target value.
            variables_json: Optional JSON object for template variables
                (e.g. {"username":"analyst","password":"secret","session_cookie":"sid=..."}).
        """
        variables: dict[str, Any] = {}
        if str(variables_json or "").strip():
            try:
                parsed = json.loads(variables_json)
            except Exception as exc:
                return {"success": False, "error": f"Invalid variables_json: {exc}"}
            if not isinstance(parsed, dict):
                return {"success": False, "error": "variables_json must be a JSON object"}
            variables = parsed
        registry = await _build_tool_registry()
        return await run_playbook_runtime(name, target, registry, variables=variables)

    @mcp.tool()
    async def list_playbook_runs_tool(name: str = "", limit: int = 50) -> dict[str, Any]:
        """List recent playbook run history."""
        return {"success": True, "runs": list_playbook_runs(playbook_name=name, limit=max(1, int(limit)))}
