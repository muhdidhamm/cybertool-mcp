"""Sprint 1 lightweight MCP tool wrappers (CLI-first integrations)."""

from tools.helpers import run_command, sanitize_arg, validate_url
import shutil


def register_sprint1_tools(mcp):
    @mcp.tool()
    async def sprint1_tools_prereq_check(timeout: int = 60) -> dict:
        """Check whether Sprint 1 CLI binaries are present in PATH.

        This helps verify that tools are callable at runtime by Claude through MCP.
        """
        required_bins = {
            "paramspider": "python3 /opt/ParamSpider/paramspider.py",
            "linkfinder": "python3 /opt/LinkFinder/linkfinder.py",
            "secretfinder": "python3 /opt/SecretFinder/SecretFinder.py",
            "hashid": "hashid",
            "fail2ban": "fail2ban-client",
            "aide": "aide",
            "pwntools_script_runner": "python3",
            "ropgadget": "ROPgadget",
            "grype": "grype",
            "syft": "syft",
            "checkov": "checkov",
            "s3scanner": "s3scanner",
            "kube_bench": "kube-bench",
            "sigma": "sigma",
            "apkleaks": "apkleaks",
            "boofuzz_script_runner": "python3",
        }
        status = {}
        for name, binary in required_bins.items():
            token = binary.split()[0]
            status[name] = {
                "required": binary,
                "available": shutil.which(token) is not None,
            }
        return {
            "success": True,
            "checked": len(required_bins),
            "available": sum(1 for v in status.values() if v["available"]),
            "status": status,
            "timeout": timeout,
        }

    @mcp.tool()
    async def paramspider_scan(domain: str, exclude: str = "", timeout: int = 300) -> dict:
        cmd = ["python3", "/opt/ParamSpider/paramspider.py", "--domain", sanitize_arg(domain)]
        if exclude:
            cmd.extend(["--exclude", sanitize_arg(exclude)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def linkfinder_scan(input_url: str, output_format: str = "cli", timeout: int = 300) -> dict:
        url = validate_url(input_url)
        out = sanitize_arg(output_format).lower()
        if out not in {"cli", "html"}:
            raise ValueError("output_format must be cli or html")
        cmd = ["python3", "/opt/LinkFinder/linkfinder.py", "-i", url, "-o", out]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def secretfinder_scan(input_url: str, regex_mode: bool = False, timeout: int = 300) -> dict:
        url = validate_url(input_url)
        cmd = ["python3", "/opt/SecretFinder/SecretFinder.py", "-i", url]
        if regex_mode:
            cmd.append("--regex")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def hashid_identify(hash_value: str, extended: bool = False, timeout: int = 300) -> dict:
        cleaned = sanitize_arg(hash_value)
        if len(cleaned) < 8:
            raise ValueError("hash_value appears too short")
        cmd = ["hashid", cleaned]
        if extended:
            cmd.append("--extended")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def fail2ban_client(action: str = "status", jail: str = "", timeout: int = 300) -> dict:
        allowed = {"status", "get", "set", "reload"}
        act = sanitize_arg(action).lower()
        if act not in allowed:
            raise ValueError(f"action must be one of: {', '.join(sorted(allowed))}")
        cmd = ["fail2ban-client", act]
        if jail:
            cmd.append(sanitize_arg(jail))
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def aide_run(mode: str = "check", config_path: str = "", timeout: int = 300) -> dict:
        mode_map = {"check": "--check", "init": "--init", "update": "--update"}
        mode_clean = sanitize_arg(mode).lower()
        if mode_clean not in mode_map:
            raise ValueError("mode must be one of: check, init, update")
        cmd = ["aide"]
        if config_path:
            cmd.extend(["--config", sanitize_arg(config_path)])
        cmd.append(mode_map[mode_clean])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def pwntools_script(script_path: str, script_args: str = "", timeout: int = 300) -> dict:
        cmd = ["python3", sanitize_arg(script_path)]
        if script_args:
            cmd.extend(sanitize_arg(script_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def ropgadget_scan(binary_path: str, options: str = "", timeout: int = 300) -> dict:
        cmd = ["ROPgadget", "--binary", sanitize_arg(binary_path)]
        if options:
            cmd.extend(sanitize_arg(options).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def grype_scan(target: str, timeout: int = 300) -> dict:
        cmd = ["grype", sanitize_arg(target)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def syft_sbom(target: str, output: str = "table", timeout: int = 300) -> dict:
        fmt = sanitize_arg(output).lower()
        allowed = {"table", "json", "spdx-json", "cyclonedx-json"}
        if fmt not in allowed:
            raise ValueError(f"output must be one of: {', '.join(sorted(allowed))}")
        cmd = ["syft", sanitize_arg(target), "-o", fmt]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def checkov_scan(directory: str = ".", framework: str = "", timeout: int = 300) -> dict:
        cmd = ["checkov", "-d", sanitize_arg(directory)]
        if framework:
            cmd.extend(["--framework", sanitize_arg(framework)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def s3scanner_scan(target: str, timeout: int = 300) -> dict:
        cmd = ["s3scanner", "scan", sanitize_arg(target)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def kube_bench_scan(timeout: int = 300) -> dict:
        cmd = ["kube-bench"]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def sigma_convert(rule_path: str, target: str, timeout: int = 300) -> dict:
        cmd = ["sigma", "convert", "-t", sanitize_arg(target), sanitize_arg(rule_path)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def apkleaks_scan(apk_path: str, timeout: int = 300) -> dict:
        cmd = ["apkleaks", "-f", sanitize_arg(apk_path)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def boofuzz_script(script_path: str, timeout: int = 300) -> dict:
        cmd = ["python3", sanitize_arg(script_path)]
        return await run_command(cmd, timeout=timeout)
