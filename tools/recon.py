"""Network scanning and reconnaissance tools: nmap, masscan, zmap, arp-scan,
traceroute, mtr, ping, p0f, hping3."""

from tools.helpers import run_command, validate_target, validate_port_range, sanitize_arg


def register_recon_tools(mcp):

    @mcp.tool()
    async def nmap_scan(
        target: str,
        scan_type: str = "-sV",
        ports: str = "",
        scripts: str = "",
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Run an Nmap scan against a target host or network.

        Args:
            target: IP, hostname, or CIDR range to scan.
            scan_type: Nmap scan flags (e.g. -sS, -sV, -sU, -A, -O). Default: -sV.
            ports: Port specification (e.g. "22,80,443" or "1-1000"). Empty = Nmap default.
            scripts: NSE scripts to run (e.g. "vuln", "http-enum,ssl-cert").
            extra_args: Any additional nmap arguments.
            timeout: Max seconds to wait. Default 300.
        """
        target = validate_target(target)
        cmd = ["nmap"]
        for flag in sanitize_arg(scan_type).split():
            cmd.append(flag)
        if ports:
            cmd.extend(["-p", validate_port_range(ports)])
        if scripts:
            cmd.extend(["--script", sanitize_arg(scripts)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        cmd.append(target)
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def masscan_scan(
        target: str,
        ports: str = "1-65535",
        rate: int = 1000,
        timeout: int = 300,
    ) -> dict:
        """Run a Masscan fast port scan.

        Args:
            target: IP or CIDR range.
            ports: Port range to scan. Default: all ports.
            rate: Packets per second. Default 1000.
            timeout: Max seconds. Default 300.
        """
        target = validate_target(target)
        cmd = [
            "masscan", target,
            "-p", validate_port_range(ports),
            "--rate", str(int(rate)),
            "--open",
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def zmap_scan(
        target: str = "0.0.0.0/0",
        port: int = 80,
        rate: int = 1000,
        timeout: int = 300,
    ) -> dict:
        """Internet-wide single-port scanning using ZMap.

        Args:
            target: Target network CIDR. Default: all (internet-wide).
            port: Single port to scan. Default 80.
            rate: Packets per second. Default 1000.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = [
            "zmap",
            "-p", str(int(port)),
            "-r", str(int(rate)),
            target,
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def arp_scan(interface: str = "eth0", network: str = "") -> dict:
        """Discover hosts on the local network via ARP.

        Args:
            interface: Network interface. Default eth0.
            network: Target network CIDR. Empty = local network.
        """
        cmd = ["arp-scan", "--interface", sanitize_arg(interface)]
        if network:
            cmd.append(validate_target(network))
        else:
            cmd.append("--localnet")
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def traceroute_host(target: str, max_hops: int = 30) -> dict:
        """Trace the route packets take to a target host.

        Args:
            target: IP or hostname.
            max_hops: Maximum TTL hops. Default 30.
        """
        target = validate_target(target)
        cmd = ["traceroute", "-m", str(int(max_hops)), target]
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def mtr_trace(
        target: str,
        count: int = 10,
        report: bool = True,
    ) -> dict:
        """Combined traceroute + ping using MTR for network path analysis.

        Args:
            target: IP or hostname.
            count: Number of pings per hop. Default 10.
            report: Report mode (finish and print). Default True.
        """
        target = validate_target(target)
        cmd = ["mtr", "--no-dns", "-c", str(int(count))]
        if report:
            cmd.append("--report")
        cmd.append(target)
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def ping_host(target: str, count: int = 4) -> dict:
        """Ping a host to check if it's alive.

        Args:
            target: IP or hostname.
            count: Number of ICMP packets. Default 4.
        """
        target = validate_target(target)
        cmd = ["fping", "-c", str(int(count)), target]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def hping3_probe(
        target: str,
        port: int = 80,
        mode: str = "-S",
        count: int = 4,
        timeout: int = 30,
    ) -> dict:
        """Advanced ping/probe using hping3 (TCP/UDP/ICMP crafting).

        Args:
            target: Target IP or hostname.
            port: Target port. Default 80.
            mode: Packet mode (-S=SYN, -A=ACK, -F=FIN, -U=UDP, --icmp). Default -S.
            count: Packet count. Default 4.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["hping3", sanitize_arg(mode), "-p", str(int(port)), "-c", str(int(count)), target]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def tcp_connect_test(target: str, port: int) -> dict:
        """Test if a specific TCP port is open using netcat.

        Args:
            target: IP or hostname.
            port: TCP port number.
        """
        target = validate_target(target)
        cmd = ["nc", "-zv", "-w", "5", target, str(int(port))]
        return await run_command(cmd, timeout=15)

    @mcp.tool()
    async def nbtscan_host(target: str) -> dict:
        """Scan for NetBIOS name information on a target or network.

        Args:
            target: IP or CIDR.
        """
        target = validate_target(target)
        cmd = ["nbtscan", "-v", target]
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def unicornscan_scan(
        target: str,
        ports: str = "1-65535",
        mode: str = "T",
        rate: int = 500,
        timeout: int = 300,
    ) -> dict:
        """Asynchronous stateless TCP/UDP scanner using Unicornscan.

        Args:
            target: Target IP.
            ports: Port range. Default all.
            mode: Scan mode (T=TCP SYN, U=UDP). Default T.
            rate: Packets per second. Default 500.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = [
            "unicornscan",
            "-m", sanitize_arg(mode),
            "-p", sanitize_arg(ports),
            "-r", str(int(rate)),
            target,
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def netdiscover_scan(
        interface: str = "eth0",
        range: str = "",
        passive: bool = False,
        timeout: int = 30,
    ) -> dict:
        """ARP-based network discovery using netdiscover.

        Args:
            interface: Network interface.
            range: Target range (e.g. "192.168.1.0/24"). Empty = auto.
            passive: Passive mode (just listen). Default False.
            timeout: Max seconds.
        """
        cmd = ["netdiscover", "-i", sanitize_arg(interface)]
        if range:
            cmd.extend(["-r", sanitize_arg(range)])
        if passive:
            cmd.append("-p")
        return await run_command(cmd, timeout=timeout)
