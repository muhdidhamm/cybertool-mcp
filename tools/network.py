"""Network tools: tcpdump, tshark, socat, proxychains, tor, iperf3."""

from tools.helpers import run_command, validate_target, sanitize_arg


def register_network_tools(mcp):

    @mcp.tool()
    async def tcpdump_capture(
        interface: str = "eth0",
        filter_expr: str = "",
        count: int = 100,
        output_file: str = "/opt/uts-mcp/output/capture.pcap",
        timeout: int = 60,
    ) -> dict:
        """Capture network packets with tcpdump.

        Args:
            interface: Network interface. Default eth0.
            filter_expr: BPF filter expression (e.g. "tcp port 80", "host 10.0.0.1").
            count: Number of packets to capture. Default 100.
            output_file: Output pcap file path.
            timeout: Max seconds.
        """
        cmd = [
            "tcpdump", "-i", sanitize_arg(interface),
            "-c", str(int(count)),
            "-w", sanitize_arg(output_file),
            "-nn",
        ]
        if filter_expr:
            cmd.extend(sanitize_arg(filter_expr).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def tcpdump_read(
        pcap_file: str,
        filter_expr: str = "",
        verbose: bool = False,
    ) -> dict:
        """Read and analyze a pcap file with tcpdump.

        Args:
            pcap_file: Path to pcap file.
            filter_expr: BPF filter expression.
            verbose: Verbose output. Default False.
        """
        cmd = ["tcpdump", "-r", sanitize_arg(pcap_file), "-nn"]
        if verbose:
            cmd.append("-vvv")
        if filter_expr:
            cmd.extend(sanitize_arg(filter_expr).split())
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def tshark_analyze(
        pcap_file: str = "",
        interface: str = "",
        display_filter: str = "",
        fields: str = "",
        count: int = 100,
        timeout: int = 60,
    ) -> dict:
        """Analyze packets using TShark (CLI Wireshark).

        Args:
            pcap_file: Path to pcap file to read. Empty = live capture.
            interface: Interface for live capture.
            display_filter: Wireshark display filter (e.g. "http.request", "tcp.port==443").
            fields: Specific fields to extract (e.g. "ip.src,ip.dst,tcp.port").
            count: Packet count limit.
            timeout: Max seconds.
        """
        cmd = ["tshark"]
        if pcap_file:
            cmd.extend(["-r", sanitize_arg(pcap_file)])
        elif interface:
            cmd.extend(["-i", sanitize_arg(interface)])
        if display_filter:
            cmd.extend(["-Y", sanitize_arg(display_filter)])
        if fields:
            cmd.append("-T")
            cmd.append("fields")
            for f in sanitize_arg(fields).split(","):
                cmd.extend(["-e", f.strip()])
        cmd.extend(["-c", str(int(count))])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def socat_relay(
        listen_port: int,
        target: str,
        target_port: int,
        protocol: str = "TCP",
    ) -> dict:
        """Set up a socat network relay / port forward.

        Args:
            listen_port: Local port to listen on.
            target: Target host to forward to.
            target_port: Target port.
            protocol: Protocol (TCP, UDP). Default TCP.
        """
        target = validate_target(target)
        proto = sanitize_arg(protocol).upper()
        cmd = [
            "socat",
            f"{proto}-LISTEN:{int(listen_port)},fork",
            f"{proto}:{target}:{int(target_port)}",
        ]
        return await run_command(cmd, timeout=10)

    @mcp.tool()
    async def proxychains_run(
        command: str,
        timeout: int = 120,
    ) -> dict:
        """Execute a command through proxychains (Tor or custom proxy).

        Args:
            command: Command to run through the proxy chain.
            timeout: Max seconds.
        """
        cmd = ["proxychains4"] + sanitize_arg(command).split()
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def iperf3_test(
        target: str,
        port: int = 5201,
        duration: int = 10,
        reverse: bool = False,
        udp: bool = False,
    ) -> dict:
        """Network bandwidth testing using iperf3.

        Args:
            target: Target iperf3 server IP.
            port: Server port. Default 5201.
            duration: Test duration in seconds. Default 10.
            reverse: Reverse mode (server sends). Default False.
            udp: UDP mode instead of TCP. Default False.
        """
        target = validate_target(target)
        cmd = [
            "iperf3", "-c", target,
            "-p", str(int(port)),
            "-t", str(int(duration)),
            "--json",
        ]
        if reverse:
            cmd.append("-R")
        if udp:
            cmd.append("-u")
        return await run_command(cmd, timeout=duration + 30)

    @mcp.tool()
    async def ssldump_capture(
        interface: str = "eth0",
        port: int = 443,
        timeout: int = 30,
    ) -> dict:
        """Capture and decode SSL/TLS traffic using ssldump.

        Args:
            interface: Network interface.
            port: Port to monitor. Default 443.
            timeout: Capture duration.
        """
        cmd = [
            "ssldump", "-i", sanitize_arg(interface),
            "-a", "-A", "-e",
            "port", str(int(port)),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def netsniff_ng_capture(
        interface: str = "eth0",
        pcap_file: str = "/opt/uts-mcp/output/capture.pcap",
        filter_expr: str = "",
        timeout: int = 30,
    ) -> dict:
        """High-performance packet capture using netsniff-ng.

        Args:
            interface: Network interface.
            pcap_file: Output pcap file path.
            filter_expr: BPF filter expression. Empty = all traffic.
            timeout: Capture duration in seconds.
        """
        cmd = ["netsniff-ng", "-i", sanitize_arg(interface), "-o", sanitize_arg(pcap_file), "-s"]
        if filter_expr:
            cmd.extend(["-f", sanitize_arg(filter_expr)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def arping_scan(
        target: str,
        interface: str = "eth0",
        count: int = 3,
        timeout: int = 15,
    ) -> dict:
        """Send ARP requests to discover hosts using arping.

        Args:
            target: Target IP address.
            interface: Network interface. Default eth0.
            count: Number of ARP requests. Default 3.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["arping", "-c", str(int(count)), "-I", sanitize_arg(interface), target]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def tor_check_circuit(timeout: int = 30) -> dict:
        """Check Tor connectivity and current exit node IP."""
        cmd = ["bash", "-c", "tor --verify-config 2>&1; curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null || echo 'Tor not running'"]
        return await run_command(cmd, timeout=timeout)
