"""Sniffing, spoofing & MITM tools: bettercap, ettercap, dsniff, mitm6, arpspoof,
sslstrip, dnschef, mitmproxy."""

from tools.helpers import run_command, validate_target, sanitize_arg


def register_sniffspoof_tools(mcp):

    @mcp.tool()
    async def bettercap_run(
        interface: str = "eth0",
        caplets: str = "",
        eval_commands: str = "",
        timeout: int = 120,
    ) -> dict:
        """Run Bettercap for network attacks, sniffing, and MITM.

        Args:
            interface: Network interface. Default eth0.
            caplets: Caplet file to load (e.g. "http-ui", "arp.spoof").
            eval_commands: Semicolon-separated commands to evaluate.
            timeout: Max seconds.
        """
        cmd = ["bettercap", "-iface", sanitize_arg(interface)]
        if caplets:
            cmd.extend(["-caplet", sanitize_arg(caplets)])
        if eval_commands:
            cmd.extend(["-eval", eval_commands])
        cmd.append("-no-colors")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def ettercap_scan(
        interface: str = "eth0",
        target1: str = "",
        target2: str = "",
        text_mode: bool = True,
        timeout: int = 60,
    ) -> dict:
        """Network sniffer and MITM attacks using Ettercap.

        Args:
            interface: Network interface. Default eth0.
            target1: First target IP. Empty = all.
            target2: Second target IP (e.g. gateway). Empty = all.
            text_mode: Text-only mode. Default True.
            timeout: Max seconds.
        """
        cmd = ["ettercap"]
        if text_mode:
            cmd.append("-T")
        cmd.extend(["-i", sanitize_arg(interface)])
        if target1:
            t = "/" + sanitize_arg(target1) + "//"
            if target2:
                t += " /" + sanitize_arg(target2) + "//"
            cmd.extend(["-M", "arp:remote", t])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dsniff_sniff(
        interface: str = "eth0",
        timeout: int = 60,
    ) -> dict:
        """Sniff passwords from network traffic using dsniff.

        Args:
            interface: Network interface.
            timeout: Capture duration.
        """
        cmd = ["dsniff", "-i", sanitize_arg(interface)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def arpspoof_attack(
        interface: str = "eth0",
        target: str = "",
        gateway: str = "",
        timeout: int = 30,
    ) -> dict:
        """ARP spoofing using arpspoof (from dsniff suite).

        Args:
            interface: Network interface.
            target: Target IP to spoof.
            gateway: Gateway IP.
            timeout: Duration in seconds.
        """
        cmd = ["arpspoof", "-i", sanitize_arg(interface)]
        if target:
            cmd.extend(["-t", sanitize_arg(target)])
        if gateway:
            cmd.append(sanitize_arg(gateway))
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def mitm6_attack(
        domain: str,
        interface: str = "eth0",
        timeout: int = 60,
    ) -> dict:
        """IPv6-based MITM attack using mitm6 to relay credentials.

        Args:
            domain: Target domain.
            interface: Network interface.
            timeout: Max seconds.
        """
        cmd = [
            "mitm6", "-d", sanitize_arg(domain),
            "-i", sanitize_arg(interface),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def p0f_fingerprint(
        interface: str = "eth0",
        pcap_file: str = "",
        timeout: int = 30,
    ) -> dict:
        """Passive OS fingerprinting using p0f.

        Args:
            interface: Network interface for live capture.
            pcap_file: Path to pcap file. Empty = live capture.
            timeout: Capture duration.
        """
        cmd = ["p0f"]
        if pcap_file:
            cmd.extend(["-r", sanitize_arg(pcap_file)])
        else:
            cmd.extend(["-i", sanitize_arg(interface)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def sslstrip_attack(
        listen_port: int = 10000,
        timeout: int = 60,
    ) -> dict:
        """HTTPS downgrade attack using sslstrip.

        Args:
            listen_port: Local listening port. Default 10000.
            timeout: Duration in seconds.
        """
        cmd = ["sslstrip", "-l", str(int(listen_port))]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dnschef_spoof(
        interface: str = "0.0.0.0",
        domain: str = "",
        fake_ip: str = "",
        timeout: int = 60,
    ) -> dict:
        """DNS proxy for traffic analysis and spoofing using dnschef.

        Args:
            interface: Listening interface. Default 0.0.0.0.
            domain: Domain to spoof. Empty = all.
            fake_ip: IP to return for spoofed queries.
            timeout: Duration in seconds.
        """
        cmd = ["dnschef", "--interface", sanitize_arg(interface)]
        if domain and fake_ip:
            cmd.extend(["--fakedomains", sanitize_arg(domain),
                         "--fakeip", sanitize_arg(fake_ip)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def mitmproxy_dump(
        listen_port: int = 8080,
        mode: str = "regular",
        timeout: int = 60,
    ) -> dict:
        """Start mitmproxy in non-interactive dump mode for HTTP/S traffic inspection.

        Args:
            listen_port: Proxy listening port. Default 8080.
            mode: Proxy mode (regular, transparent, upstream). Default regular.
            timeout: Duration in seconds.
        """
        cmd = ["mitmdump", "--listen-port", str(int(listen_port)),
               "--mode", sanitize_arg(mode)]
        return await run_command(cmd, timeout=timeout)
