"""VoIP security tools: sipvicious, sipp, enumiax, inviteflood, rtpbreak, etc."""

from tools.helpers import run_command, validate_target, sanitize_arg


def register_voip_tools(mcp):

    @mcp.tool()
    async def svmap_scan(
        target: str,
        port: int = 5060,
        timeout: int = 120,
    ) -> dict:
        """Scan for SIP devices on a network using svmap (SIPVicious).

        Args:
            target: Target IP, CIDR, or range.
            port: SIP port. Default 5060.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = ["svmap", target, "-p", str(int(port))]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def svwar_enumerate(
        target: str,
        extension_range: str = "100-999",
        timeout: int = 120,
    ) -> dict:
        """Enumerate SIP extensions on a PBX using svwar (SIPVicious).

        Args:
            target: Target SIP server IP.
            extension_range: Extension range to scan. Default "100-999".
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["svwar", "-e", sanitize_arg(extension_range), target]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def svcrack_crack(
        target: str,
        extension: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        timeout: int = 300,
    ) -> dict:
        """Crack SIP extension passwords using svcrack (SIPVicious).

        Args:
            target: Target SIP server.
            extension: SIP extension to crack.
            wordlist: Password wordlist.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = [
            "svcrack",
            "-u", sanitize_arg(extension),
            "-d", sanitize_arg(wordlist),
            target,
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def enumiax_scan(
        target: str,
        timeout: int = 60,
    ) -> dict:
        """Enumerate IAX2 (Asterisk) usernames using enumIAX.

        Args:
            target: Target Asterisk server.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["enumiax", "-v", target]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def inviteflood_attack(
        target: str,
        extension: str,
        domain: str,
        interface: str = "eth0",
        count: int = 1,
    ) -> dict:
        """SIP/SDP INVITE flood testing using inviteflood.

        Args:
            target: Target IP.
            extension: Target SIP extension/user.
            domain: SIP domain.
            interface: Network interface. Default eth0.
            count: Number of INVITE packets. Default 1.
        """
        target = validate_target(target)
        cmd = [
            "inviteflood",
            sanitize_arg(interface),
            sanitize_arg(extension),
            sanitize_arg(domain),
            target,
            str(int(count)),
        ]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def sipp_test(
        target: str,
        scenario: str = "uac",
        calls: int = 1,
        rate: int = 1,
        timeout: int = 60,
    ) -> dict:
        """SIP protocol performance testing using SIPp.

        Args:
            target: Target SIP server (ip:port).
            scenario: Scenario (uac, uas, or custom XML path). Default uac.
            calls: Number of calls. Default 1.
            rate: Calls per second. Default 1.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = [
            "sipp", target,
            "-sn", sanitize_arg(scenario),
            "-m", str(int(calls)),
            "-r", str(int(rate)),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def rtpbreak_analyze(
        interface: str = "eth0",
        timeout: int = 30,
    ) -> dict:
        """Detect and reconstruct RTP streams using rtpbreak.

        Args:
            interface: Network interface.
            timeout: Capture duration in seconds.
        """
        cmd = ["rtpbreak", "-i", sanitize_arg(interface)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def sctpscan_scan(
        target: str,
        ports: str = "1-10000",
        timeout: int = 120,
    ) -> dict:
        """SCTP port scanner using sctpscan.

        Args:
            target: Target IP.
            ports: Port range. Default "1-10000".
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["sctpscan", "-s", target, "-p", sanitize_arg(ports)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def iaxflood_attack(
        target: str,
        source: str = "127.0.0.1",
        num_packets: int = 1000,
        timeout: int = 30,
    ) -> dict:
        """IAX2 flood attack for VoIP stress testing using iaxflood.

        Args:
            target: Target IP.
            source: Source IP. Default 127.0.0.1.
            num_packets: Number of packets. Default 1000.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["iaxflood", sanitize_arg(source), target, str(int(num_packets))]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def rtpinsertsound_inject(
        target: str,
        port: int = 0,
        wav_file: str = "",
        timeout: int = 30,
    ) -> dict:
        """Inject audio into an RTP stream using rtpinsertsound.

        Args:
            target: Target IP.
            port: RTP port.
            wav_file: Path to WAV file to inject.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["rtpinsertsound", target]
        if port > 0:
            cmd.append(str(int(port)))
        if wav_file:
            cmd.append(sanitize_arg(wav_file))
        return await run_command(cmd, timeout=timeout)
