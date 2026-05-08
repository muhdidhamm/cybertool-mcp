"""Stress testing / DoS simulation tools: slowhttptest, t50, goldeneye, siege, hping3 flood."""

from tools.helpers import run_command, validate_target, sanitize_arg


def register_stress_tools(mcp):

    @mcp.tool()
    async def slowhttptest_attack(
        target: str,
        attack_type: str = "slowloris",
        connections: int = 1000,
        duration: int = 60,
        timeout: int = 120,
    ) -> dict:
        """Application-layer DoS simulation using SlowHTTPTest.

        Args:
            target: Target URL (e.g. https://target.com/).
            attack_type: Attack type — slowloris, slowbody, slowread, range. Default slowloris.
            connections: Number of connections. Default 1000.
            duration: Test duration in seconds. Default 60.
            timeout: Max seconds for the tool.
        """
        target = sanitize_arg(target)
        type_flags = {
            "slowloris": "-H",
            "slowbody": "-B",
            "slowread": "-X",
            "range": "-R",
        }
        flag = type_flags.get(attack_type, "-H")
        cmd = [
            "slowhttptest", flag,
            "-u", target,
            "-c", str(int(connections)),
            "-l", str(int(duration)),
            "-o", "/opt/uts-mcp/output/slowhttp_result",
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def siege_test(
        target: str,
        concurrent: int = 25,
        duration: str = "30S",
        timeout: int = 120,
    ) -> dict:
        """HTTP load testing and benchmarking using Siege.

        Args:
            target: Target URL.
            concurrent: Number of concurrent users. Default 25.
            duration: Test duration (e.g. "30S", "1M", "1H"). Default 30S.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = [
            "siege", "-b",
            "-c", str(int(concurrent)),
            "-t", sanitize_arg(duration),
            target,
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def goldeneye_test(
        target: str,
        workers: int = 10,
        sockets: int = 500,
        method: str = "get",
        timeout: int = 120,
    ) -> dict:
        """HTTP DoS testing via Keep-Alive and NoCache vectors using GoldenEye.

        Args:
            target: Target URL.
            workers: Number of worker threads. Default 10.
            sockets: Number of sockets per worker. Default 500.
            method: HTTP method (get, post, random). Default get.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = [
            "goldeneye", target,
            "-w", str(int(workers)),
            "-s", str(int(sockets)),
            "-m", sanitize_arg(method),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def t50_flood(
        target: str,
        protocol: str = "TCP",
        flood: bool = True,
        timeout: int = 30,
    ) -> dict:
        """Multi-protocol packet injector using t50 for stress testing.

        Args:
            target: Target IP.
            protocol: Protocol (TCP, UDP, ICMP, etc.). Default TCP.
            flood: Enable flood mode. Default True.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["t50", target, "--protocol", sanitize_arg(protocol)]
        if flood:
            cmd.append("--flood")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dhcpig_exhaust(
        interface: str = "eth0",
        timeout: int = 30,
    ) -> dict:
        """DHCP exhaustion attack — consume all available DHCP leases using DHCPig.

        Args:
            interface: Network interface. Default eth0.
            timeout: Duration in seconds.
        """
        cmd = ["pig.py", sanitize_arg(interface)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def thc_ssl_dos(
        target: str,
        port: int = 443,
        timeout: int = 30,
    ) -> dict:
        """SSL renegotiation stress test using THC-SSL-DOS.

        Args:
            target: Target IP or hostname.
            port: Target port. Default 443.
            timeout: Duration in seconds.
        """
        target = validate_target(target)
        cmd = ["thc-ssl-dos", target, str(int(port)), "--accept"]
        return await run_command(cmd, timeout=timeout)
