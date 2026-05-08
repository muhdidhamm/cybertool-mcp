"""OSINT & information gathering tools: theHarvester, fierce, dnsenum, dnsrecon,
amass, sublist3r, subfinder, httpx, dmitry, whois, sherlock, spiderfoot,
dnstwist, snmp, shodan."""

from tools.helpers import run_command, validate_target, sanitize_arg


def register_osint_tools(mcp):

    @mcp.tool()
    async def theharvester_search(
        domain: str,
        source: str = "all",
        limit: int = 200,
        timeout: int = 300,
    ) -> dict:
        """Gather emails, subdomains, hosts, and names from public sources using theHarvester.

        Args:
            domain: Target domain name.
            source: Data source (google, bing, linkedin, all, etc.). Default: all.
            limit: Maximum results. Default 200.
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = [
            "theHarvester",
            "-d", domain,
            "-b", sanitize_arg(source),
            "-l", str(int(limit)),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def fierce_scan(domain: str, timeout: int = 120) -> dict:
        """DNS reconnaissance using Fierce to find non-contiguous IP ranges.

        Args:
            domain: Target domain.
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = ["fierce", "--domain", domain]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dnsenum_scan(
        domain: str,
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Enumerate DNS information for a domain using dnsenum.

        Args:
            domain: Target domain.
            extra_args: Additional dnsenum arguments.
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = ["dnsenum", domain]
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dnsrecon_scan(
        domain: str,
        record_type: str = "std",
        timeout: int = 120,
    ) -> dict:
        """DNS reconnaissance using dnsrecon.

        Args:
            domain: Target domain.
            record_type: Enumeration type (std, brt, srv, axfr, rvl). Default: std.
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = ["dnsrecon", "-d", domain, "-t", sanitize_arg(record_type)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dnsmap_scan(
        domain: str,
        wordlist: str = "",
        timeout: int = 300,
    ) -> dict:
        """Subdomain brute-force using dnsmap.

        Args:
            domain: Target domain.
            wordlist: Custom wordlist path. Empty = built-in.
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = ["dnsmap", domain]
        if wordlist:
            cmd.extend(["-w", sanitize_arg(wordlist)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dnstwist_scan(
        domain: str,
        timeout: int = 120,
    ) -> dict:
        """Find lookalike/typosquat domains using dnstwist.

        Args:
            domain: Target domain to check for permutations.
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = ["dnstwist", "--registered", domain]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def amass_enum(
        domain: str,
        passive: bool = True,
        timeout: int = 300,
    ) -> dict:
        """Subdomain enumeration using Amass.

        Args:
            domain: Target domain.
            passive: Passive-only mode (no active probing). Default True.
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = ["amass", "enum", "-d", domain]
        if passive:
            cmd.append("-passive")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def sublist3r_enum(
        domain: str,
        engines: str = "",
        timeout: int = 120,
    ) -> dict:
        """Fast subdomain enumeration using Sublist3r.

        Args:
            domain: Target domain.
            engines: Specific search engines (e.g. "google,bing,virustotal").
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = ["sublist3r", "-d", domain]
        if engines:
            cmd.extend(["-e", sanitize_arg(engines)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def subfinder_enum(
        domain: str,
        sources: str = "",
        timeout: int = 120,
    ) -> dict:
        """Fast passive subdomain discovery using Subfinder.

        Args:
            domain: Target domain.
            sources: Specific sources (comma-separated). Empty = all.
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = ["subfinder", "-d", domain, "-silent"]
        if sources:
            cmd.extend(["-sources", sanitize_arg(sources)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def assetfinder_enum(
        domain: str,
        subs_only: bool = True,
        timeout: int = 60,
    ) -> dict:
        """Find related domains and subdomains using Assetfinder.

        Args:
            domain: Target domain.
            subs_only: Only show subdomains. Default True.
            timeout: Max seconds.
        """
        domain = validate_target(domain)
        cmd = ["assetfinder"]
        if subs_only:
            cmd.append("--subs-only")
        cmd.append(domain)
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def httpx_probe(
        targets: str,
        ports: str = "",
        status_code: bool = True,
        title: bool = True,
        tech_detect: bool = True,
        timeout: int = 120,
    ) -> dict:
        """Probe HTTP servers for live hosts using httpx.

        Args:
            targets: Target(s) — URL, hostname, or newline-separated list.
            ports: Custom ports to probe (e.g. "80,443,8080,8443").
            status_code: Show status codes. Default True.
            title: Show page titles. Default True.
            tech_detect: Detect technologies. Default True.
            timeout: Max seconds.
        """
        cmd = ["httpx", "-silent"]
        if status_code:
            cmd.append("-sc")
        if title:
            cmd.append("-title")
        if tech_detect:
            cmd.append("-td")
        if ports:
            cmd.extend(["-ports", sanitize_arg(ports)])
        cmd.extend(["-u", sanitize_arg(targets)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def naabu_portscan(
        target: str,
        ports: str = "",
        top_ports: int = 100,
        timeout: int = 120,
    ) -> dict:
        """Fast port scanner using Naabu (by ProjectDiscovery).

        Args:
            target: Target IP or hostname.
            ports: Specific ports (e.g. "22,80,443"). Empty = top ports.
            top_ports: Number of top ports to scan. Default 100.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["naabu", "-host", target, "-silent"]
        if ports:
            cmd.extend(["-p", sanitize_arg(ports)])
        else:
            cmd.extend(["-top-ports", str(int(top_ports))])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dmitry_scan(
        target: str,
        whois: bool = True,
        subdomains: bool = True,
        emails: bool = True,
        ports: bool = False,
    ) -> dict:
        """Deepmagic Information Gathering Tool — WHOIS, subdomains, emails, port scan.

        Args:
            target: Target domain or IP.
            whois: Perform WHOIS lookup. Default True.
            subdomains: Search for subdomains. Default True.
            emails: Search for email addresses. Default True.
            ports: Perform TCP port scan. Default False.
        """
        target = validate_target(target)
        flags = "-"
        if whois:
            flags += "w"
        if subdomains:
            flags += "s"
        if emails:
            flags += "e"
        if ports:
            flags += "p"
        if flags == "-":
            flags = "-wse"
        cmd = ["dmitry", flags, target]
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def whois_lookup(target: str) -> dict:
        """Perform a WHOIS lookup on a domain or IP.

        Args:
            target: Domain name or IP address.
        """
        target = validate_target(target)
        cmd = ["whois", target]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def dig_lookup(
        target: str,
        record_type: str = "ANY",
        server: str = "",
    ) -> dict:
        """DNS lookup using dig.

        Args:
            target: Domain name to query.
            record_type: DNS record type (A, AAAA, MX, NS, TXT, ANY, etc.). Default ANY.
            server: DNS server to query (e.g. 8.8.8.8). Empty = system default.
        """
        target = validate_target(target)
        cmd = ["dig"]
        if server:
            cmd.append("@" + validate_target(server))
        cmd.extend([target, sanitize_arg(record_type).upper()])
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def enum4linux_scan(target: str, extra_args: str = "") -> dict:
        """Enumerate information from Windows/Samba hosts using enum4linux.

        Args:
            target: Target IP or hostname.
            extra_args: Additional enum4linux flags (e.g. "-a" for full enum).
        """
        target = validate_target(target)
        cmd = ["enum4linux"]
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        else:
            cmd.append("-a")
        cmd.append(target)
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def sherlock_search(
        username: str,
        timeout: int = 120,
    ) -> dict:
        """Hunt for social media accounts by username across platforms using Sherlock.

        Args:
            username: Username to search for.
            timeout: Max seconds.
        """
        cmd = ["sherlock", sanitize_arg(username), "--print-found"]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def spiderfoot_scan(
        target: str,
        modules: str = "",
        timeout: int = 600,
    ) -> dict:
        """OSINT automation using SpiderFoot CLI.

        Args:
            target: Target domain, IP, email, or username.
            modules: Specific modules to run (comma-separated). Empty = all.
            timeout: Max seconds.
        """
        cmd = ["spiderfoot", "-s", sanitize_arg(target), "-q"]
        if modules:
            cmd.extend(["-m", sanitize_arg(modules)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def snmpwalk_scan(
        target: str,
        community: str = "public",
        version: str = "2c",
        oid: str = "",
        timeout: int = 60,
    ) -> dict:
        """SNMP enumeration using snmpwalk.

        Args:
            target: Target IP or hostname.
            community: SNMP community string. Default "public".
            version: SNMP version (1, 2c, 3). Default 2c.
            oid: Specific OID to query. Empty = walk full tree.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = [
            "snmpwalk",
            "-v", sanitize_arg(version),
            "-c", sanitize_arg(community),
            target,
        ]
        if oid:
            cmd.append(sanitize_arg(oid))
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def onesixtyone_scan(
        target: str,
        community_file: str = "",
        timeout: int = 60,
    ) -> dict:
        """Fast SNMP community string scanner using onesixtyone.

        Args:
            target: Target IP or file with IPs.
            community_file: File with community strings to try. Empty = defaults.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = ["onesixtyone"]
        if community_file:
            cmd.extend(["-c", sanitize_arg(community_file)])
        cmd.append(target)
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def shodan_search(
        query: str,
        api_key: str = "",
        limit: int = 10,
    ) -> dict:
        """Search Shodan for internet-connected devices (requires API key).

        Args:
            query: Shodan search query.
            api_key: Shodan API key. Set via SHODAN_API_KEY env var if empty.
            limit: Max results. Default 10.
        """
        cmd = ["shodan", "search", "--limit", str(int(limit))]
        cmd.append(sanitize_arg(query))
        env = {}
        if api_key:
            env["SHODAN_API_KEY"] = sanitize_arg(api_key)
        return await run_command(cmd, timeout=30, env=env if env else None)

    @mcp.tool()
    async def shodan_host(
        ip: str,
        api_key: str = "",
    ) -> dict:
        """Get Shodan information for a specific IP address.

        Args:
            ip: Target IP address.
            api_key: Shodan API key.
        """
        ip = validate_target(ip)
        cmd = ["shodan", "host", ip]
        env = {}
        if api_key:
            env["SHODAN_API_KEY"] = sanitize_arg(api_key)
        return await run_command(cmd, timeout=30, env=env if env else None)

    @mcp.tool()
    async def recon_ng_run(
        workspace: str = "default",
        commands: str = "",
        timeout: int = 120,
    ) -> dict:
        """Run Recon-ng OSINT framework commands non-interactively.

        Args:
            workspace: Workspace name. Default "default".
            commands: Semicolon-separated commands (e.g. "marketplace install all; modules load recon/domains-hosts/hackertarget; options set SOURCE target.com; run").
            timeout: Max seconds.
        """
        cmd_str = "; ".join(sanitize_arg(c).strip() for c in commands.split(";") if c.strip())
        cmd = ["bash", "-c", f"echo '{cmd_str}' | recon-ng -w {sanitize_arg(workspace)} --no-analytics"]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def certbot_check(
        domain: str,
        timeout: int = 30,
    ) -> dict:
        """Check SSL certificate details and renewal status using Certbot.

        Args:
            domain: Domain to check.
            timeout: Max seconds.
        """
        cmd = ["certbot", "certificates", "-d", sanitize_arg(domain)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def tlsx_scan(
        target: str,
        port: int = 443,
        timeout: int = 30,
    ) -> dict:
        """Fast TLS probe using tlsx — grab certs, detect misconfigurations.

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["tlsx", "-host", f"{target}:{int(port)}", "-json"]
        return await run_command(cmd, timeout=timeout)
