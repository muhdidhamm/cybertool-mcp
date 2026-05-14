"""Vulnerability scanning tools: wpscan, lynis, chkrootkit, rkhunter, clamav, nmap-vuln."""

from tools.helpers import run_command, validate_url, validate_target, sanitize_arg


def register_vuln_tools(mcp):

    @mcp.tool()
    async def gitleaks_scan(
        source_path: str = ".",
        config_path: str = "",
        redact: bool = True,
        timeout: int = 300,
    ) -> dict:
        """Detect hardcoded secrets in source code using Gitleaks.

        Args:
            source_path: Repository or directory path to scan.
            config_path: Optional custom gitleaks config path.
            redact: Redact secret values in output. Default True.
            timeout: Max seconds.
        """
        cmd = ["gitleaks", "detect", "--source", sanitize_arg(source_path)]
        if config_path:
            cmd.extend(["--config", sanitize_arg(config_path)])
        if redact:
            cmd.append("--redact")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def trufflehog_scan(
        target: str,
        as_json: bool = True,
        timeout: int = 300,
    ) -> dict:
        """Scan filesystem path for leaked secrets using TruffleHog.

        Args:
            target: File or directory path to scan.
            as_json: Emit JSON lines output. Default True.
            timeout: Max seconds.
        """
        cmd = ["trufflehog", "filesystem", sanitize_arg(target)]
        if as_json:
            cmd.append("--json")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def trivy_scan(
        target: str,
        scan_type: str = "fs",
        severity: str = "",
        timeout: int = 300,
    ) -> dict:
        """Run Trivy vulnerability scans for filesystem/image/repository targets.

        Args:
            target: Scan target path/image/repository.
            scan_type: One of fs, image, repo. Default fs.
            severity: Optional comma-separated severity filter.
            timeout: Max seconds.
        """
        scan_mode = sanitize_arg(scan_type).lower()
        if scan_mode not in {"fs", "image", "repo"}:
            raise ValueError("scan_type must be one of: fs, image, repo")
        cmd = ["trivy", scan_mode, sanitize_arg(target), "--no-progress"]
        if severity:
            cmd.extend(["--severity", sanitize_arg(severity).upper()])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def wpscan(
        url: str,
        enumerate: str = "vp,vt,u",
        api_token: str = "",
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Scan a WordPress site for vulnerabilities using WPScan.

        Args:
            url: WordPress site URL.
            enumerate: Enumeration options (vp=vulnerable plugins, vt=vulnerable themes,
                       u=users, ap=all plugins, at=all themes, cb=config backups). Default: vp,vt,u.
            api_token: WPScan API token for vulnerability data (optional).
            extra_args: Additional WPScan arguments.
            timeout: Max seconds.
        """
        url = validate_url(url)
        cmd = ["wpscan", "--url", url, "--enumerate", sanitize_arg(enumerate)]
        if api_token:
            cmd.extend(["--api-token", sanitize_arg(api_token)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        cmd.append("--no-banner")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def lynis_audit(
        profile: str = "",
        tests: str = "",
        timeout: int = 600,
    ) -> dict:
        """Run a Lynis security audit on the system.

        Args:
            profile: Audit profile to use. Empty = default.
            tests: Specific tests to run (e.g. "BOOT-5180,AUTH-9262"). Empty = all.
            timeout: Max seconds.
        """
        cmd = ["lynis", "audit", "system", "--no-colors", "--quick"]
        if profile:
            cmd.extend(["--profile", sanitize_arg(profile)])
        if tests:
            cmd.extend(["--tests", sanitize_arg(tests)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def chkrootkit_scan(timeout: int = 120) -> dict:
        """Check for rootkits using chkrootkit.

        Args:
            timeout: Max seconds.
        """
        cmd = ["chkrootkit"]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def rkhunter_scan(
        update_first: bool = False,
        timeout: int = 300,
    ) -> dict:
        """Scan for rootkits, backdoors, and local exploits using rkhunter.

        Args:
            update_first: Update definitions before scanning. Default False.
            timeout: Max seconds.
        """
        if update_first:
            await run_command(["rkhunter", "--update"], timeout=60)
        cmd = ["rkhunter", "--check", "--skip-keypress", "--no-colors"]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def clamav_scan(
        path: str = "/opt/uts-mcp/output",
        recursive: bool = True,
        timeout: int = 300,
    ) -> dict:
        """Scan files for malware using ClamAV.

        Args:
            path: File or directory to scan.
            recursive: Recurse into directories. Default True.
            timeout: Max seconds.
        """
        cmd = ["clamscan"]
        if recursive:
            cmd.append("-r")
        cmd.append(sanitize_arg(path))
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def nmap_script_scan(
        target: str,
        scripts: str,
        ports: str = "",
        script_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Run specific Nmap NSE scripts against a target.

        Args:
            target: Target IP, hostname, or CIDR.
            scripts: NSE scripts to run (e.g. "http-enum", "smb-vuln*", "ftp-anon").
            ports: Port specification. Empty = auto.
            script_args: Script arguments (e.g. "http-enum.basepath=/admin/").
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["nmap", "--script", sanitize_arg(scripts), "-sV"]
        if ports:
            from tools.helpers import validate_port_range
            cmd.extend(["-p", validate_port_range(ports)])
        if script_args:
            cmd.extend(["--script-args", sanitize_arg(script_args)])
        cmd.append(target)
        return await run_command(cmd, timeout=timeout)
