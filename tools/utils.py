"""Utility tools: file management, system info, wordlist helpers, IP calculation, DB updates."""

import json
import os
import csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from tools.helpers import run_command, sanitize_arg, save_output, OUTPUT_DIR
from tools.time_utils import configured_timezone, format_now_tz

VALID_UPDATE_TOOLS = frozenset([
    "nmap", "metasploit", "nuclei", "wpscan", "clamav",
    "exploitdb", "nikto", "rkhunter", "lynis", "subfinder",
    "amass", "wapiti", "hashcat",
])


def _parse_iso8601_utc(raw_value: str, field: str) -> datetime:
    value = sanitize_arg(raw_value).strip()
    if not value:
        raise ValueError(f"{field} cannot be empty")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(configured_timezone())


def register_util_tools(mcp):

    @mcp.tool()
    async def list_output_files() -> dict:
        """List all files in the MCP output directory."""
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        files = []
        for p in sorted(OUTPUT_DIR.rglob("*")):
            if p.is_file():
                stat = p.stat()
                files.append({
                    "path": str(p),
                    "size_bytes": stat.st_size,
                    "modified": stat.st_mtime,
                })
        return {"success": True, "files": files, "count": len(files)}

    @mcp.tool()
    async def read_output_file(file_path: str, max_bytes: int = 100000) -> dict:
        """Read the contents of a file in the output directory.

        Args:
            file_path: Path to the file.
            max_bytes: Maximum bytes to read. Default 100000.
        """
        path = Path(sanitize_arg(file_path))
        if not path.exists():
            return {"success": False, "error": f"File not found: {path}"}
        try:
            content = path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
            return {"success": True, "path": str(path), "content": content}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    async def write_file(file_path: str, content: str) -> dict:
        """Write content to a file inside the output directory.

        Args:
            file_path: Filename or path relative to /opt/uts-mcp/output.
            content: Content to write.
        """
        full_path = save_output(file_path, content)
        return {"success": True, "path": full_path}

    @mcp.tool()
    async def ipcalc(cidr: str) -> dict:
        """Calculate IP network information from a CIDR notation.

        Args:
            cidr: IP/CIDR notation (e.g. "192.168.1.0/24").
        """
        cmd = ["ipcalc", sanitize_arg(cidr)]
        return await run_command(cmd, timeout=5)

    @mcp.tool()
    async def list_wordlists() -> dict:
        """List available wordlists in common locations."""
        locations = [
            "/usr/share/wordlists",
            "/usr/share/seclists",
        ]
        wordlists = []
        for loc in locations:
            p = Path(loc)
            if p.exists():
                for f in sorted(p.rglob("*.txt"))[:200]:
                    wordlists.append({
                        "path": str(f),
                        "size_mb": round(f.stat().st_size / 1_048_576, 2),
                    })
        return {"success": True, "wordlists": wordlists, "count": len(wordlists)}

    @mcp.tool()
    async def system_info() -> dict:
        """Get system information about the Cybertool MCP container."""
        uname = await run_command(["uname", "-a"], timeout=5)
        ip = await run_command(["ip", "addr", "show"], timeout=5)
        ps = await run_command(["ps", "aux"], timeout=5)
        disk = await run_command(["df", "-h"], timeout=5)
        return {
            "success": True,
            "uname": uname.get("stdout", ""),
            "network": ip.get("stdout", ""),
            "processes": ps.get("stdout", ""),
            "disk": disk.get("stdout", ""),
        }

    @mcp.tool()
    async def shell_exec(
        command: str,
        timeout: int = 60,
    ) -> dict:
        """Execute an arbitrary shell command inside the Cybertool MCP container.

        Use this for any tool or command not covered by the specialized tools.
        Commands run as root inside the container.

        Args:
            command: Shell command to execute.
            timeout: Max seconds. Default 60.
        """
        cmd = ["bash", "-c", command]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def curl_request(
        url: str,
        method: str = "GET",
        headers: str = "",
        data: str = "",
        follow_redirects: bool = True,
        timeout: int = 30,
    ) -> dict:
        """Make HTTP requests using curl.

        Args:
            url: Target URL.
            method: HTTP method. Default GET.
            headers: Headers as "Key: Value" lines separated by newlines.
            data: Request body data.
            follow_redirects: Follow HTTP redirects. Default True.
            timeout: Max seconds.
        """
        cmd = ["curl", "-s", "-S", "-D-"]
        if method.upper() != "GET":
            cmd.extend(["-X", sanitize_arg(method).upper()])
        if follow_redirects:
            cmd.append("-L")
        if data:
            cmd.extend(["-d", data])
        if headers:
            for h in headers.strip().split("\n"):
                h = h.strip()
                if h:
                    cmd.extend(["-H", h])
        cmd.extend(["--max-time", str(int(timeout))])
        cmd.append(sanitize_arg(url))
        return await run_command(cmd, timeout=timeout + 5)

    @mcp.tool()
    async def download_file(
        url: str,
        output_path: str = "",
        timeout: int = 120,
    ) -> dict:
        """Download a file using wget.

        Args:
            url: URL to download.
            output_path: Output file path. Empty = auto-name in output dir.
            timeout: Max seconds.
        """
        cmd = ["wget", "-q"]
        if output_path:
            cmd.extend(["-O", sanitize_arg(output_path)])
        else:
            cmd.extend(["-P", str(OUTPUT_DIR)])
        cmd.append(sanitize_arg(url))
        return await run_command(cmd, timeout=timeout)

    # ── Database / Pattern Update Tools ──────────────────────────────────

    @mcp.tool()
    async def update_all_databases(timeout: int = 600) -> dict:
        """Update ALL tool databases, signatures, and templates to their latest versions.

        This updates: Nmap scripts, Metasploit modules, Nuclei templates,
        WPScan DB, ClamAV signatures, ExploitDB, Nikto plugins, rkhunter,
        Lynis, Subfinder, Amass, Wapiti, and Hashcat rules.

        Updates are stored on a persistent volume and survive container restarts.

        Args:
            timeout: Max seconds to wait. Default 600 (10 minutes).
        """
        cmd = ["/opt/uts-mcp/update-databases.sh", "all"]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def update_tool_database(
        tool: str,
        timeout: int = 300,
    ) -> dict:
        """Update the database/signatures for a single tool.

        Supported tools: nmap, metasploit, nuclei, wpscan, clamav,
        exploitdb, nikto, rkhunter, lynis, subfinder, amass, wapiti, hashcat.

        Args:
            tool: Tool name to update.
            timeout: Max seconds. Default 300.
        """
        tool_name = sanitize_arg(tool).lower().strip()
        if tool_name == "msf":
            tool_name = "metasploit"
        if tool_name == "searchsploit":
            tool_name = "exploitdb"
        if tool_name not in VALID_UPDATE_TOOLS:
            return {
                "success": False,
                "error": f"Unknown tool '{tool_name}'. Supported: {', '.join(sorted(VALID_UPDATE_TOOLS))}",
            }
        cmd = ["/opt/uts-mcp/update-databases.sh", tool_name]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def database_update_status() -> dict:
        """Show the last update timestamp for every tool database.

        Returns when each tool's database was last updated and the total
        size of persistent data.
        """
        cmd = ["/opt/uts-mcp/update-databases.sh", "--check"]
        return await run_command(cmd, timeout=10)

    # ── Additional utility tools ─────────────────────────────────────────

    @mcp.tool()
    async def powershell_exec(
        script: str,
        timeout: int = 60,
    ) -> dict:
        """Execute a PowerShell command or script inside the Cybertool MCP container.

        Args:
            script: PowerShell command or script block.
            timeout: Max seconds.
        """
        cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def cutycapt_screenshot(
        url: str,
        output_file: str = "/opt/uts-mcp/output/screenshot.png",
        timeout: int = 30,
    ) -> dict:
        """Capture a webpage screenshot using CutyCapt.

        Args:
            url: Target URL.
            output_file: Output image path (.png, .jpg, .pdf).
            timeout: Max seconds.
        """
        cmd = [
            "cutycapt",
            f"--url={sanitize_arg(url)}",
            f"--out={sanitize_arg(output_file)}",
            "--insecure",
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def pipal_analyze(
        wordlist: str,
        output_file: str = "/opt/uts-mcp/output/pipal_analysis.txt",
        timeout: int = 120,
    ) -> dict:
        """Analyze a password list for patterns and statistics using Pipal.

        Args:
            wordlist: Path to password list file.
            output_file: Output file for analysis.
            timeout: Max seconds.
        """
        cmd = ["pipal", sanitize_arg(wordlist), "--output", sanitize_arg(output_file)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def maskprocessor_generate(
        mask: str,
        output_file: str = "/opt/uts-mcp/output/generated_wordlist.txt",
        timeout: int = 60,
    ) -> dict:
        """Generate word candidates from a mask pattern using maskprocessor.

        Args:
            mask: Mask pattern (?l=lowercase, ?u=uppercase, ?d=digit, ?s=special, e.g. "?u?l?l?l?d?d?d?d").
            output_file: Output wordlist path.
            timeout: Max seconds.
        """
        cmd = ["maskprocessor", sanitize_arg(mask), "-o", sanitize_arg(output_file)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def bluetooth_scan(
        interface: str = "hci0",
        duration: int = 10,
        timeout: int = 30,
    ) -> dict:
        """Scan for nearby Bluetooth devices using hcitool and btscanner.

        Args:
            interface: Bluetooth interface. Default hci0.
            duration: Scan duration in seconds.
            timeout: Max seconds.
        """
        scan_result = await run_command(
            ["hcitool", "-i", sanitize_arg(interface), "scan", "--length", str(int(duration))],
            timeout=timeout
        )
        info_result = await run_command(
            ["hcitool", "-i", sanitize_arg(interface), "dev"],
            timeout=5
        )
        return {
            "success": True,
            "devices_found": scan_result.get("stdout", ""),
            "local_adapter": info_result.get("stdout", ""),
            "scan_errors": scan_result.get("stderr", ""),
        }

    @mcp.tool()
    async def bluelog_discover(
        interface: str = "hci0",
        duration: int = 30,
        output_file: str = "/opt/uts-mcp/output/bluelog.log",
        timeout: int = 60,
    ) -> dict:
        """Log discovered Bluetooth devices using Bluelog.

        Args:
            interface: Bluetooth interface. Default hci0.
            duration: Discovery duration.
            output_file: Log output file.
            timeout: Max seconds.
        """
        cmd = [
            "bluelog", "-i", sanitize_arg(interface),
            "-o", sanitize_arg(output_file),
            "-t", str(int(duration)),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def audit_log_guery(
        event_type: str = "",
        tool_name: str = "",
        contains: str = "",
        since: str = "",
        until: str = "",
        limit: int = 100,
        offset: int = 0,
        log_path: str = "",
    ) -> dict:
        """Query MCP audit logs with optional filters.

        Args:
            event_type: Filter by event type (e.g. tool.invoke, command.result).
            tool_name: Filter by payload.tool.
            contains: Case-insensitive substring match against serialized payload.
            since: ISO-8601 lower bound (inclusive), e.g. 2026-04-06T00:00:00Z.
            until: ISO-8601 upper bound (inclusive), e.g. 2026-04-06T23:59:59Z.
            limit: Max events to return. Default 100, max 1000.
            offset: Skip first N matching events. Default 0.
            log_path: Optional explicit path. Defaults to MCP_AUDIT_LOG_PATH or standard path.
        """
        safe_event_type = sanitize_arg(event_type).strip()
        safe_tool_name = sanitize_arg(tool_name).strip()
        safe_contains = sanitize_arg(contains).strip().lower()
        safe_offset = max(0, int(offset))
        safe_limit = min(1000, max(1, int(limit)))

        if log_path.strip():
            path = Path(sanitize_arg(log_path).strip())
        else:
            path = Path(
                os.environ.get("MCP_AUDIT_LOG_PATH", "/opt/uts-mcp/logs/mcp_audit.jsonl")
            )

        if not path.exists():
            return {"success": False, "error": f"Audit log file not found: {path}"}

        since_dt = _parse_iso8601_utc(since, "since") if since.strip() else None
        until_dt = _parse_iso8601_utc(until, "until") if until.strip() else None

        if since_dt and until_dt and since_dt > until_dt:
            return {"success": False, "error": "'since' cannot be later than 'until'"}

        matched: list[dict] = []
        scanned_lines = 0
        skipped = 0
        parse_errors = 0

        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                scanned_lines += 1
                try:
                    event = json.loads(line)
                except Exception:
                    parse_errors += 1
                    continue

                if safe_event_type and event.get("event_type") != safe_event_type:
                    continue

                payload = event.get("payload", {})
                payload_tool = ""
                if isinstance(payload, dict):
                    payload_tool = str(payload.get("tool", ""))
                if safe_tool_name and payload_tool != safe_tool_name:
                    continue

                ts_raw = str(event.get("timestamp", "")).strip()
                try:
                    ts_parsed = _parse_iso8601_utc(ts_raw, "timestamp")
                except Exception:
                    ts_parsed = None
                if since_dt and ts_parsed and ts_parsed < since_dt:
                    continue
                if until_dt and ts_parsed and ts_parsed > until_dt:
                    continue

                if safe_contains:
                    blob = json.dumps(event, ensure_ascii=True).lower()
                    if safe_contains not in blob:
                        continue

                if skipped < safe_offset:
                    skipped += 1
                    continue
                if len(matched) >= safe_limit:
                    continue

                matched.append(event)

        return {
            "success": True,
            "path": str(path),
            "filters": {
                "event_type": safe_event_type,
                "tool_name": safe_tool_name,
                "contains": safe_contains,
                "since": since,
                "until": until,
                "limit": safe_limit,
                "offset": safe_offset,
            },
            "scanned_lines": scanned_lines,
            "parse_errors": parse_errors,
            "returned": len(matched),
            "events": matched,
        }

    @mcp.tool()
    async def audit_log_query(
        event_type: str = "",
        tool_name: str = "",
        contains: str = "",
        since: str = "",
        until: str = "",
        limit: int = 100,
        offset: int = 0,
        log_path: str = "",
    ) -> dict:
        """Alias for audit_log_guery with corrected spelling."""
        return await audit_log_guery(
            event_type=event_type,
            tool_name=tool_name,
            contains=contains,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
            log_path=log_path,
        )

    @mcp.tool()
    async def audit_log_export_csv(
        event_type: str = "",
        tool_name: str = "",
        contains: str = "",
        since: str = "",
        until: str = "",
        limit: int = 1000,
        offset: int = 0,
        log_path: str = "",
        output_path: str = "",
    ) -> dict:
        """Export filtered audit events to CSV for SIEM/analyst workflows.

        Args:
            event_type: Filter by event type.
            tool_name: Filter by payload.tool.
            contains: Case-insensitive substring match.
            since: ISO-8601 lower bound (inclusive).
            until: ISO-8601 upper bound (inclusive).
            limit: Max events to export. Default 1000, max 5000.
            offset: Skip first N matching events.
            log_path: Optional explicit audit log path.
            output_path: Optional output CSV path. Auto-generated if empty.
        """
        safe_limit = min(5000, max(1, int(limit)))
        query_result = await audit_log_guery(
            event_type=event_type,
            tool_name=tool_name,
            contains=contains,
            since=since,
            until=until,
            limit=safe_limit,
            offset=offset,
            log_path=log_path,
        )
        if not query_result.get("success"):
            return query_result

        if output_path.strip():
            csv_path = Path(sanitize_arg(output_path).strip())
        else:
            ts = format_now_tz("%Y%m%d_%H%M%S")
            csv_path = Path(f"/opt/uts-mcp/reports/audit_export_{ts}.csv")

        csv_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "timestamp",
            "event_type",
            "tool",
            "elapsed_seconds",
            "success",
            "return_code",
            "error",
            "error_type",
            "command",
            "payload_json",
        ]

        events = query_result.get("events", [])
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                payload = event.get("payload", {})
                if not isinstance(payload, dict):
                    payload = {"raw_payload": payload}
                writer.writerow(
                    {
                        "timestamp": event.get("timestamp", ""),
                        "event_type": event.get("event_type", ""),
                        "tool": payload.get("tool", ""),
                        "elapsed_seconds": payload.get("elapsed_seconds", payload.get("elapsed", "")),
                        "success": payload.get("success", ""),
                        "return_code": payload.get("return_code", ""),
                        "error": payload.get("error", ""),
                        "error_type": payload.get("error_type", ""),
                        "command": payload.get("command", ""),
                        "payload_json": json.dumps(payload, ensure_ascii=True),
                    }
                )

        return {
            "success": True,
            "path": str(csv_path),
            "exported": len(events),
            "filters": query_result.get("filters", {}),
            "scanned_lines": query_result.get("scanned_lines", 0),
            "parse_errors": query_result.get("parse_errors", 0),
        }

    @mcp.tool()
    async def audit_log_stats(
        event_type: str = "",
        tool_name: str = "",
        contains: str = "",
        since: str = "",
        until: str = "",
        limit: int = 5000,
        offset: int = 0,
        log_path: str = "",
        top_n: int = 10,
        bucket_minutes: int = 0,
    ) -> dict:
        """Compute summary statistics from filtered audit events.

        Args:
            event_type: Optional event type filter.
            tool_name: Optional payload.tool filter.
            contains: Optional case-insensitive text filter.
            since: ISO-8601 lower bound (inclusive).
            until: ISO-8601 upper bound (inclusive).
            limit: Max events to include. Default 5000.
            offset: Skip first N matching events.
            log_path: Optional explicit audit log path.
            top_n: Number of top entries for ranked lists. Default 10.
            bucket_minutes: Optional time-bucket size (minutes). 0 disables buckets.
        """
        safe_top_n = min(100, max(1, int(top_n)))
        safe_limit = min(20_000, max(1, int(limit)))
        safe_bucket_minutes = max(0, int(bucket_minutes))

        query_result = await audit_log_guery(
            event_type=event_type,
            tool_name=tool_name,
            contains=contains,
            since=since,
            until=until,
            limit=safe_limit,
            offset=offset,
            log_path=log_path,
        )
        if not query_result.get("success"):
            return query_result

        events = query_result.get("events", [])
        total_events = len(events)
        event_counter: Counter[str] = Counter()
        tool_counter: Counter[str] = Counter()
        command_counter: Counter[str] = Counter()
        error_counter: Counter[str] = Counter()
        success_true = 0
        success_false = 0
        durations: list[float] = []
        bucket_counter: Counter[str] = Counter()

        def _parse_ts(ts_value: str) -> datetime | None:
            ts = str(ts_value).strip()
            if not ts:
                return None
            try:
                return _parse_iso8601_utc(ts, "timestamp")
            except Exception:
                return None

        for event in events:
            ev_type = str(event.get("event_type", ""))
            if ev_type:
                event_counter[ev_type] += 1

            payload = event.get("payload", {})
            if not isinstance(payload, dict):
                payload = {"raw_payload": payload}

            tool = str(payload.get("tool", "")).strip()
            if tool:
                tool_counter[tool] += 1

            command = payload.get("command")
            if isinstance(command, list):
                cmd_text = " ".join(str(x) for x in command)
            else:
                cmd_text = str(command or "").strip()
            if cmd_text:
                command_counter[cmd_text] += 1

            error = str(payload.get("error", "")).strip()
            if error:
                error_counter[error] += 1

            success_value = payload.get("success")
            if success_value is True:
                success_true += 1
            elif success_value is False:
                success_false += 1

            elapsed = payload.get("elapsed_seconds", payload.get("elapsed"))
            try:
                if elapsed is not None and str(elapsed).strip() != "":
                    durations.append(float(elapsed))
            except Exception:
                pass

            if safe_bucket_minutes > 0:
                ts_dt = _parse_ts(event.get("timestamp", ""))
                if ts_dt:
                    minute_slot = (ts_dt.minute // safe_bucket_minutes) * safe_bucket_minutes
                    bucket_dt = ts_dt.replace(minute=minute_slot, second=0, microsecond=0)
                    bucket_counter[bucket_dt.isoformat()] += 1

        success_total = success_true + success_false
        success_rate = (success_true / success_total) if success_total else None
        failure_rate = (success_false / success_total) if success_total else None

        duration_stats = {}
        if durations:
            ordered = sorted(durations)
            duration_stats = {
                "count": len(ordered),
                "min_seconds": round(ordered[0], 4),
                "max_seconds": round(ordered[-1], 4),
                "avg_seconds": round(sum(ordered) / len(ordered), 4),
                "p50_seconds": round(ordered[len(ordered) // 2], 4),
                "p95_seconds": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 4),
            }

        return {
            "success": True,
            "filters": query_result.get("filters", {}),
            "source": {
                "path": query_result.get("path", ""),
                "scanned_lines": query_result.get("scanned_lines", 0),
                "parse_errors": query_result.get("parse_errors", 0),
                "considered_events": total_events,
            },
            "summary": {
                "events_total": total_events,
                "events_by_type": dict(event_counter),
                "success_true": success_true,
                "success_false": success_false,
                "success_rate": round(success_rate, 4) if success_rate is not None else None,
                "failure_rate": round(failure_rate, 4) if failure_rate is not None else None,
            },
            "top_tools": [{"tool": k, "count": v} for k, v in tool_counter.most_common(safe_top_n)],
            "top_commands": [{"command": k, "count": v} for k, v in command_counter.most_common(safe_top_n)],
            "top_errors": [{"error": k, "count": v} for k, v in error_counter.most_common(safe_top_n)],
            "duration_seconds": duration_stats,
            "time_buckets": (
                [{"bucket_start": k, "count": v} for k, v in sorted(bucket_counter.items())]
                if safe_bucket_minutes > 0 else []
            ),
            "meta": {
                "top_n": safe_top_n,
                "bucket_minutes": safe_bucket_minutes,
            },
        }
