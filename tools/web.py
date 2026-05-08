"""Web application security tools: nikto, dirb, gobuster, ffuf, feroxbuster, sqlmap,
whatweb, wafw00f, sslscan, sslyze, wfuzz, joomscan, droopescan, commix, xsser,
wapiti, skipfish, testssl."""

from tools.helpers import run_command, validate_url, validate_target, sanitize_arg


def register_web_tools(mcp):

    @mcp.tool()
    async def nikto_scan(
        target: str,
        port: int = 0,
        ssl: bool = False,
        tuning: str = "",
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Run Nikto web server vulnerability scanner. Supports both HTTP and HTTPS.

        Args:
            target: URL or hostname of the web server (use https:// for SSL sites).
            port: Port number (0 = auto-detect from URL).
            ssl: Force SSL mode. Auto-detected if target starts with https://. Default False.
            tuning: Nikto tuning string (e.g. "123bde" for specific test categories).
            extra_args: Additional nikto arguments.
            timeout: Max seconds. Default 300.
        """
        target = sanitize_arg(target)
        use_ssl = ssl or target.startswith("https://")
        cmd = ["nikto", "-h", target]
        if port > 0:
            cmd.extend(["-p", str(int(port))])
        if use_ssl:
            cmd.append("-ssl")
        if tuning:
            cmd.extend(["-Tuning", sanitize_arg(tuning)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dirb_scan(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extensions: str = "",
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Brute-force directories and files on a web server using DIRB.

        Args:
            url: Target URL (e.g. http://target.com).
            wordlist: Path to wordlist file.
            extensions: File extensions to check (e.g. "php,html,txt").
            extra_args: Additional dirb arguments.
            timeout: Max seconds. Default 300.
        """
        url = validate_url(url)
        cmd = ["dirb", url, sanitize_arg(wordlist)]
        if extensions:
            cmd.extend(["-X", sanitize_arg(extensions)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def gobuster_dir(
        url: str,
        wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
        extensions: str = "",
        threads: int = 10,
        status_codes: str = "200,204,301,302,307,401,403",
        insecure_ssl: bool = True,
        timeout: int = 300,
    ) -> dict:
        """Directory/file brute-forcing with Gobuster. Works with both HTTP and HTTPS.

        Args:
            url: Target URL (http:// or https://).
            wordlist: Wordlist path.
            extensions: Extensions to search (e.g. "php,html").
            threads: Concurrent threads. Default 10.
            status_codes: Status codes to include. Default common codes.
            insecure_ssl: Skip SSL certificate verification for HTTPS. Default True.
            timeout: Max seconds.
        """
        url = validate_url(url)
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", sanitize_arg(wordlist),
            "-t", str(int(threads)),
            "-s", sanitize_arg(status_codes),
            "--no-error",
        ]
        if insecure_ssl:
            cmd.append("-k")
        if extensions:
            cmd.extend(["-x", sanitize_arg(extensions)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def ffuf_fuzz(
        url: str,
        wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
        method: str = "GET",
        filter_code: str = "",
        match_code: str = "200,204,301,302,307,401,403",
        headers: str = "",
        data: str = "",
        threads: int = 40,
        timeout: int = 300,
    ) -> dict:
        """Fast web fuzzer using ffuf. Use FUZZ as placeholder in URL, headers, or data.
        Works with both HTTP and HTTPS URLs (SSL verification disabled by default).

        Args:
            url: URL with FUZZ keyword (e.g. https://target.com/FUZZ).
            wordlist: Wordlist path.
            method: HTTP method. Default GET.
            filter_code: HTTP codes to filter OUT (e.g. "404,403").
            match_code: HTTP codes to match/show (e.g. "200,301"). Ignored if filter_code set.
            headers: Extra headers as "Key: Value" separated by semicolons.
            data: POST data (use FUZZ as placeholder).
            threads: Concurrent threads. Default 40.
            timeout: Max seconds.
        """
        url = sanitize_arg(url)
        cmd = [
            "ffuf",
            "-u", url,
            "-w", sanitize_arg(wordlist),
            "-t", str(int(threads)),
            "-X", sanitize_arg(method).upper(),
        ]
        if filter_code:
            cmd.extend(["-fc", sanitize_arg(filter_code)])
        elif match_code:
            cmd.extend(["-mc", sanitize_arg(match_code)])
        if headers:
            for h in sanitize_arg(headers).split(";"):
                h = h.strip()
                if h:
                    cmd.extend(["-H", h])
        if data:
            cmd.extend(["-d", sanitize_arg(data)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def feroxbuster_scan(
        url: str,
        wordlist: str = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        extensions: str = "",
        threads: int = 50,
        depth: int = 2,
        status_codes: str = "200,204,301,302,307,401,403,405",
        insecure_ssl: bool = True,
        timeout: int = 300,
    ) -> dict:
        """Recursive content discovery with Feroxbuster. Works with HTTP and HTTPS.

        Args:
            url: Target URL (http:// or https://).
            wordlist: Wordlist path.
            extensions: Extensions to search (e.g. "php,html,js").
            threads: Concurrent threads. Default 50.
            depth: Recursion depth. Default 2.
            status_codes: Status codes to include.
            insecure_ssl: Skip SSL cert verification for HTTPS. Default True.
            timeout: Max seconds.
        """
        url = validate_url(url)
        cmd = [
            "feroxbuster",
            "-u", url,
            "-w", sanitize_arg(wordlist),
            "-t", str(int(threads)),
            "-d", str(int(depth)),
            "-s", sanitize_arg(status_codes),
            "-q",
        ]
        if insecure_ssl:
            cmd.append("-k")
        if extensions:
            cmd.extend(["-x", sanitize_arg(extensions)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def sqlmap_scan(
        url: str,
        data: str = "",
        method: str = "GET",
        level: int = 1,
        risk: int = 1,
        force_ssl: bool = False,
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Run SQLMap to detect and exploit SQL injection vulnerabilities.
        Supports HTTPS URLs natively — pass https:// URLs directly.

        Args:
            url: Target URL with injectable parameter (e.g. https://target.com/page?id=1).
            data: POST data string (for POST-based injection).
            method: HTTP method. Default GET.
            level: Test level 1-5. Default 1.
            risk: Risk level 1-3. Default 1.
            force_ssl: Force SSL/HTTPS even if URL is http://. Default False.
            extra_args: Additional sqlmap arguments.
            timeout: Max seconds. Default 300.
        """
        url = validate_url(url)
        cmd = [
            "sqlmap", "-u", url,
            "--batch",
            "--level", str(int(level)),
            "--risk", str(int(risk)),
        ]
        if force_ssl:
            cmd.append("--force-ssl")
        if data:
            cmd.extend(["--data", sanitize_arg(data)])
            cmd.extend(["--method", sanitize_arg(method).upper()])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def commix_scan(
        url: str,
        data: str = "",
        level: int = 1,
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Test for command injection vulnerabilities using Commix.

        Args:
            url: Target URL with injectable parameter.
            data: POST data string.
            level: Test level 1-3. Default 1.
            extra_args: Additional commix arguments.
            timeout: Max seconds.
        """
        url = validate_url(url)
        cmd = ["commix", "--url", url, "--batch", "--level", str(int(level))]
        if data:
            cmd.extend(["--data", sanitize_arg(data)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def xsser_scan(
        url: str,
        auto: bool = True,
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Detect and exploit XSS vulnerabilities using XSSer.

        Args:
            url: Target URL with injectable parameter.
            auto: Auto-detect injection point. Default True.
            extra_args: Additional xsser arguments.
            timeout: Max seconds.
        """
        url = validate_url(url)
        cmd = ["xsser", "-u", url]
        if auto:
            cmd.append("--auto")
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def joomscan_scan(url: str, timeout: int = 300) -> dict:
        """Scan Joomla CMS sites for vulnerabilities using JoomScan.

        Args:
            url: Target Joomla site URL.
            timeout: Max seconds.
        """
        url = validate_url(url)
        cmd = ["joomscan", "--url", url]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def droopescan_scan(
        url: str,
        cms: str = "drupal",
        timeout: int = 300,
    ) -> dict:
        """Scan CMS sites (Drupal, WordPress, Joomla, SilverStripe, Moodle) for vulnerabilities.

        Args:
            url: Target URL.
            cms: CMS type (drupal, wordpress, joomla, silverstripe, moodle). Default drupal.
            timeout: Max seconds.
        """
        url = validate_url(url)
        cmd = ["droopescan", "scan", sanitize_arg(cms), "-u", url]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def wapiti_scan(
        url: str,
        scope: str = "page",
        modules: str = "",
        timeout: int = 600,
    ) -> dict:
        """Web application vulnerability scanner using Wapiti.

        Args:
            url: Target URL.
            scope: Scan scope (page, folder, domain, punk). Default page.
            modules: Specific modules to run (e.g. "sql,xss,exec"). Empty = all.
            timeout: Max seconds.
        """
        url = validate_url(url)
        cmd = ["wapiti", "-u", url, "-s", sanitize_arg(scope)]
        if modules:
            cmd.extend(["-m", sanitize_arg(modules)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def whatweb_scan(target: str, aggression: int = 1) -> dict:
        """Identify web technologies, CMS, frameworks on a target.

        Args:
            target: URL or hostname.
            aggression: Aggression level 1-4. Default 1 (stealthy).
        """
        target = sanitize_arg(target)
        cmd = ["whatweb", "-a", str(int(aggression)), target]
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def wafw00f_detect(url: str) -> dict:
        """Detect Web Application Firewalls protecting a target.

        Args:
            url: Target URL.
        """
        url = validate_url(url)
        cmd = ["wafw00f", url]
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def sslscan_check(target: str) -> dict:
        """Analyze SSL/TLS configuration and vulnerabilities.

        Args:
            target: Hostname or IP:port.
        """
        target = sanitize_arg(target)
        cmd = ["sslscan", target]
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def sslyze_check(target: str) -> dict:
        """Deep SSL/TLS analysis using SSLyze.

        Args:
            target: Hostname or hostname:port.
        """
        target = sanitize_arg(target)
        cmd = ["sslyze", target]
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def testssl_check(target: str, timeout: int = 300) -> dict:
        """Comprehensive SSL/TLS testing using testssl.sh.

        Args:
            target: Hostname or hostname:port.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = ["testssl", "--color", "0", target]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def wfuzz_scan(
        url: str,
        wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
        hide_codes: str = "404",
        timeout: int = 300,
    ) -> dict:
        """Fuzz web applications with Wfuzz. Use FUZZ as placeholder in URL.

        Args:
            url: URL with FUZZ placeholder (e.g. http://target.com/FUZZ).
            wordlist: Wordlist path.
            hide_codes: HTTP codes to hide from output. Default "404".
            timeout: Max seconds.
        """
        url = sanitize_arg(url)
        cmd = [
            "wfuzz",
            "-w", sanitize_arg(wordlist),
            "--hc", sanitize_arg(hide_codes),
            url,
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def nuclei_scan(
        target: str,
        templates: str = "",
        severity: str = "",
        tags: str = "",
        extra_args: str = "",
        timeout: int = 600,
    ) -> dict:
        """Fast vulnerability scanner using Nuclei with YAML templates.

        Args:
            target: Target URL or hostname.
            templates: Specific template paths or IDs (comma-separated).
            severity: Filter by severity (info, low, medium, high, critical).
            tags: Filter by tags (e.g. "cve,rce,sqli").
            extra_args: Additional nuclei arguments.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        await run_command(["nuclei", "-update-templates", "-silent"], timeout=120)
        cmd = ["nuclei", "-u", target, "-silent"]
        if templates:
            cmd.extend(["-t", sanitize_arg(templates)])
        if severity:
            cmd.extend(["-severity", sanitize_arg(severity)])
        if tags:
            cmd.extend(["-tags", sanitize_arg(tags)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def zap_scan(
        target: str,
        scan_type: str = "baseline",
        extra_args: str = "",
        timeout: int = 600,
    ) -> dict:
        """Run OWASP ZAP (Zed Attack Proxy) automated scan.

        Args:
            target: Target URL.
            scan_type: Scan type — baseline, full-scan, or api-scan. Default baseline.
            extra_args: Additional arguments.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        script_map = {
            "baseline": "zap-baseline.py",
            "full-scan": "zap-full-scan.py",
            "api-scan": "zap-api-scan.py",
        }
        script = script_map.get(scan_type, "zap-baseline.py")
        cmd = [script, "-t", target, "-r", "/opt/uts-mcp/output/zap-report.html"]
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def skipfish_scan(
        target: str,
        output_dir: str = "/opt/uts-mcp/output/skipfish",
        wordlist: str = "",
        timeout: int = 600,
    ) -> dict:
        """Active web application security reconnaissance using Skipfish.

        Args:
            target: Target URL.
            output_dir: Output directory for report.
            wordlist: Custom wordlist. Empty = default.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = ["skipfish", "-o", sanitize_arg(output_dir)]
        if wordlist:
            cmd.extend(["-W", sanitize_arg(wordlist)])
        cmd.append(target)
        return await run_command(cmd, timeout=timeout)
