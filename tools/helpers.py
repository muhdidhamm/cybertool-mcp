import asyncio
import os
import re
import time
from pathlib import Path
from tools.audit_logger import write_audit_event

OUTPUT_DIR = Path("/opt/uts-mcp/output")
LOG_DIR = Path("/opt/uts-mcp/logs")

MAX_OUTPUT_BYTES = 500_000
COMMAND_TIMEOUT = 600


def sanitize_arg(value: str) -> str:
    """Strip shell metacharacters to prevent injection."""
    return re.sub(r"[;&|`$(){}!\\\n\r]", "", value).strip()


def validate_target(target: str) -> str:
    """Basic validation for hostnames / IPs / CIDRs."""
    target = sanitize_arg(target)
    pattern = re.compile(
        r"^("
        r"(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?"  # IPv4 / CIDR
        r"|([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"  # hostname
        r"|([0-9a-fA-F:]+(/\d{1,3})?)"  # IPv6
        r")$"
    )
    if not pattern.match(target):
        raise ValueError(f"Invalid target: {target}")
    return target


def validate_port_range(ports: str) -> str:
    ports = sanitize_arg(ports)
    if not re.match(r"^[\d,\-T:U:]+$", ports):
        raise ValueError(f"Invalid port spec: {ports}")
    return ports


def validate_url(url: str) -> str:
    url = sanitize_arg(url)
    if not re.match(r"^https?://", url):
        raise ValueError(f"URL must start with http:// or https://: {url}")
    return url


async def run_command(
    cmd: list[str],
    timeout: int = COMMAND_TIMEOUT,
    cwd: str | None = None,
    env: dict | None = None,
) -> dict:
    """Execute a command asynchronously and capture output."""
    start = time.time()
    merged_env = {**os.environ, **(env or {})}
    write_audit_event(
        "command.invoke",
        {
            "command": cmd,
            "timeout": timeout,
            "cwd": cwd or "",
        },
    )

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=merged_env,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass
        elapsed = round(time.time() - start, 2)
        write_audit_event(
            "command.timeout",
            {
                "command": cmd,
                "timeout": timeout,
                "elapsed": elapsed,
                "return_code": proc.returncode if proc is not None else None,
            },
        )
        return {
            "success": False,
            "error": f"Command timed out after {timeout}s",
            "command": " ".join(cmd),
            "elapsed": elapsed,
        }
    except asyncio.CancelledError:
        elapsed = round(time.time() - start, 2)
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass
        write_audit_event(
            "command.cancelled",
            {
                "command": cmd,
                "elapsed": elapsed,
                "return_code": proc.returncode if proc is not None else None,
            },
        )
        raise
    except Exception as e:
        elapsed = round(time.time() - start, 2)
        write_audit_event(
            "command.error",
            {
                "command": cmd,
                "elapsed": elapsed,
                "error": str(e),
                "error_type": type(e).__name__,
            },
        )
        return {
            "success": False,
            "error": str(e),
            "command": " ".join(cmd),
            "elapsed": elapsed,
        }
    except BaseException as e:
        elapsed = round(time.time() - start, 2)
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass
        write_audit_event(
            "command.error",
            {
                "command": cmd,
                "elapsed": elapsed,
                "error": str(e),
                "error_type": type(e).__name__,
                "base_exception": True,
            },
        )
        raise

    stdout = stdout_bytes.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]
    stderr = stderr_bytes.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]
    elapsed = round(time.time() - start, 2)

    write_audit_event(
        "command.result",
        {
            "command": cmd,
            "success": proc.returncode == 0,
            "return_code": proc.returncode,
            "elapsed": elapsed,
            "stdout": stdout,
            "stderr": stderr,
        },
    )

    return {
        "success": proc.returncode == 0,
        "return_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "command": " ".join(cmd),
        "elapsed": elapsed,
    }


def save_output(filename: str, content: str) -> str:
    """Persist tool output to the shared output directory."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / sanitize_arg(filename)
    path.write_text(content, encoding="utf-8")
    return str(path)
