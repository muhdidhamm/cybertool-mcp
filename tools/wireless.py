"""Wireless security tools: aircrack-ng suite, wifite, reaver, kismet, macchanger, etc."""

from tools.helpers import run_command, sanitize_arg


def register_wireless_tools(mcp):

    @mcp.tool()
    async def airmon_start(interface: str = "wlan0") -> dict:
        """Enable monitor mode on a wireless interface using airmon-ng.

        Args:
            interface: Wireless interface name. Default wlan0.
        """
        cmd = ["airmon-ng", "start", sanitize_arg(interface)]
        return await run_command(cmd, timeout=15)

    @mcp.tool()
    async def airmon_stop(interface: str = "wlan0mon") -> dict:
        """Disable monitor mode on a wireless interface.

        Args:
            interface: Monitor-mode interface name. Default wlan0mon.
        """
        cmd = ["airmon-ng", "stop", sanitize_arg(interface)]
        return await run_command(cmd, timeout=15)

    @mcp.tool()
    async def airodump_scan(
        interface: str = "wlan0mon",
        channel: int = 0,
        bssid: str = "",
        output_prefix: str = "/opt/uts-mcp/output/airodump",
        timeout: int = 30,
    ) -> dict:
        """Capture wireless packets and list nearby access points using airodump-ng.

        Args:
            interface: Monitor-mode interface. Default wlan0mon.
            channel: Specific channel to scan (0 = all channels).
            bssid: Filter by specific BSSID.
            output_prefix: Output file prefix.
            timeout: Capture duration in seconds. Default 30.
        """
        cmd = ["airodump-ng", sanitize_arg(interface)]
        if channel > 0:
            cmd.extend(["-c", str(int(channel))])
        if bssid:
            cmd.extend(["--bssid", sanitize_arg(bssid)])
        cmd.extend(["-w", sanitize_arg(output_prefix), "--output-format", "csv"])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def aireplay_deauth(
        interface: str = "wlan0mon",
        bssid: str = "",
        client: str = "",
        count: int = 5,
    ) -> dict:
        """Send deauthentication frames using aireplay-ng.

        Args:
            interface: Monitor-mode interface.
            bssid: Target access point BSSID.
            client: Target client MAC address (empty = broadcast).
            count: Number of deauth frames. Default 5.
        """
        cmd = [
            "aireplay-ng", "--deauth", str(int(count)),
            "-a", sanitize_arg(bssid),
        ]
        if client:
            cmd.extend(["-c", sanitize_arg(client)])
        cmd.append(sanitize_arg(interface))
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def aircrack_crack(
        capture_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        bssid: str = "",
    ) -> dict:
        """Crack WPA/WPA2 handshake using aircrack-ng with a wordlist.

        Args:
            capture_file: Path to .cap capture file with handshake.
            wordlist: Wordlist path.
            bssid: Target BSSID.
        """
        cmd = ["aircrack-ng", "-w", sanitize_arg(wordlist)]
        if bssid:
            cmd.extend(["-b", sanitize_arg(bssid)])
        cmd.append(sanitize_arg(capture_file))
        return await run_command(cmd, timeout=600)

    @mcp.tool()
    async def wifite_attack(
        interface: str = "wlan0",
        target_bssid: str = "",
        wpa_only: bool = False,
        wep_only: bool = False,
        timeout: int = 300,
    ) -> dict:
        """Automated wireless auditing using Wifite2.

        Args:
            interface: Wireless interface.
            target_bssid: Specific target BSSID. Empty = scan all.
            wpa_only: Only attack WPA/WPA2 networks.
            wep_only: Only attack WEP networks.
            timeout: Max seconds.
        """
        cmd = ["wifite", "-i", sanitize_arg(interface)]
        if target_bssid:
            cmd.extend(["--bssid", sanitize_arg(target_bssid)])
        if wpa_only:
            cmd.append("--wpa")
        if wep_only:
            cmd.append("--wep")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def reaver_attack(
        interface: str = "wlan0mon",
        bssid: str = "",
        channel: int = 0,
        pixie_dust: bool = True,
        timeout: int = 600,
    ) -> dict:
        """WPS brute-force attack using Reaver.

        Args:
            interface: Monitor-mode interface.
            bssid: Target AP BSSID.
            channel: AP channel.
            pixie_dust: Use Pixie Dust attack (faster). Default True.
            timeout: Max seconds.
        """
        cmd = ["reaver", "-i", sanitize_arg(interface), "-b", sanitize_arg(bssid)]
        if channel > 0:
            cmd.extend(["-c", str(int(channel))])
        if pixie_dust:
            cmd.append("-K")
        cmd.append("-vv")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def kismet_scan(
        interface: str = "wlan0",
        timeout: int = 60,
    ) -> dict:
        """Wireless network detector and sniffer using Kismet (headless mode).

        Args:
            interface: Wireless interface.
            timeout: Capture duration in seconds.
        """
        cmd = [
            "kismet",
            "-c", sanitize_arg(interface),
            "--no-ncurses",
            "-t", str(int(timeout)),
        ]
        return await run_command(cmd, timeout=timeout + 15)

    @mcp.tool()
    async def macchanger_change(
        interface: str,
        mac: str = "",
        random: bool = True,
    ) -> dict:
        """Change MAC address of a network interface using macchanger.

        Args:
            interface: Network interface.
            mac: Specific MAC address to set. Empty with random=True = random MAC.
            random: Use random MAC. Default True.
        """
        cmd = ["macchanger"]
        if mac:
            cmd.extend(["-m", sanitize_arg(mac)])
        elif random:
            cmd.append("-r")
        cmd.append(sanitize_arg(interface))
        return await run_command(cmd, timeout=10)

    @mcp.tool()
    async def macchanger_show(interface: str) -> dict:
        """Show current MAC address of an interface.

        Args:
            interface: Network interface.
        """
        cmd = ["macchanger", "-s", sanitize_arg(interface)]
        return await run_command(cmd, timeout=5)

    @mcp.tool()
    async def hcxdumptool_capture(
        interface: str = "wlan0",
        output_file: str = "/opt/uts-mcp/output/hcxdump.pcapng",
        timeout: int = 60,
    ) -> dict:
        """Capture PMKID and handshakes for hashcat cracking using hcxdumptool.

        Args:
            interface: Wireless interface.
            output_file: Output pcapng file.
            timeout: Capture duration in seconds.
        """
        cmd = [
            "hcxdumptool",
            "-i", sanitize_arg(interface),
            "-o", sanitize_arg(output_file),
            "--enable_status=1",
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def hcxpcapngtool_convert(
        input_file: str,
        output_file: str = "/opt/uts-mcp/output/hashes.22000",
    ) -> dict:
        """Convert pcapng captures to hashcat-compatible hash format using hcxpcapngtool.

        Args:
            input_file: Input pcapng file.
            output_file: Output hash file.
        """
        cmd = [
            "hcxpcapngtool",
            "-o", sanitize_arg(output_file),
            sanitize_arg(input_file),
        ]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def cowpatty_crack(
        capture_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        ssid: str = "",
    ) -> dict:
        """Offline WPA/WPA2 dictionary attack using coWPAtty.

        Args:
            capture_file: Path to capture file.
            wordlist: Wordlist path.
            ssid: Target network SSID.
        """
        cmd = [
            "cowpatty",
            "-f", sanitize_arg(wordlist),
            "-r", sanitize_arg(capture_file),
        ]
        if ssid:
            cmd.extend(["-s", sanitize_arg(ssid)])
        return await run_command(cmd, timeout=600)

    @mcp.tool()
    async def wavemon_info() -> dict:
        """Get wireless interface signal and link quality info using wavemon."""
        cmd = ["wavemon", "-d"]
        return await run_command(cmd, timeout=10)

    @mcp.tool()
    async def bully_attack(
        interface: str = "wlan0mon",
        bssid: str = "",
        channel: int = 0,
        timeout: int = 600,
    ) -> dict:
        """WPS brute-force attack using Bully (alternative to Reaver).

        Args:
            interface: Monitor-mode interface.
            bssid: Target AP BSSID.
            channel: AP channel.
            timeout: Max seconds.
        """
        cmd = ["bully", sanitize_arg(interface), "-b", sanitize_arg(bssid)]
        if channel > 0:
            cmd.extend(["-c", str(int(channel))])
        cmd.append("-v3")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def pyrit_attack(
        capture_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        essid: str = "",
        timeout: int = 600,
    ) -> dict:
        """GPU-accelerated WPA/WPA2 cracking using Pyrit.

        Args:
            capture_file: Path to .cap capture file.
            wordlist: Wordlist path.
            essid: Target ESSID. Empty = auto-detect from capture.
            timeout: Max seconds.
        """
        cmd = ["pyrit", "-r", sanitize_arg(capture_file), "-i", sanitize_arg(wordlist)]
        if essid:
            cmd.extend(["-e", sanitize_arg(essid)])
        cmd.append("attack_passthrough")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def hashcat_wifi_crack(
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        rules: str = "",
        timeout: int = 600,
    ) -> dict:
        """Crack WPA/WPA2 hashes (mode 22000) using Hashcat.
        Use hcxpcapngtool to convert captures to .22000 format first.

        Args:
            hash_file: Path to .22000 hash file.
            wordlist: Wordlist path.
            rules: Rules file path for mutations.
            timeout: Max seconds.
        """
        cmd = [
            "hashcat",
            "-m", "22000",
            "-a", "0",
            "--force",
            sanitize_arg(hash_file),
            sanitize_arg(wordlist),
        ]
        if rules:
            cmd.extend(["-r", sanitize_arg(rules)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def wifiphisher_attack(
        interface: str = "wlan0",
        essid: str = "",
        phishing_scenario: str = "firmware-upgrade",
        timeout: int = 300,
    ) -> dict:
        """Automated WiFi phishing / evil twin attack using Wifiphisher.

        Args:
            interface: Wireless interface.
            essid: Target network name.
            phishing_scenario: Phishing scenario (firmware-upgrade, oauth-login, plugin_update).
            timeout: Max seconds.
        """
        cmd = ["wifiphisher", "-aI", sanitize_arg(interface)]
        if essid:
            cmd.extend(["-e", sanitize_arg(essid)])
        cmd.extend(["-p", sanitize_arg(phishing_scenario)])
        cmd.append("--no-extensions")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def airgeddon_run(
        interface: str = "wlan0",
        timeout: int = 300,
    ) -> dict:
        """Multi-purpose wireless auditing framework using airgeddon (batch mode).

        Args:
            interface: Wireless interface.
            timeout: Max seconds.
        """
        cmd = ["bash", "-c", f"echo '1\n{sanitize_arg(interface)}' | airgeddon"]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def wifi_full_crack_pipeline(
        interface: str = "wlan0",
        bssid: str = "",
        channel: int = 0,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        capture_duration: int = 30,
        timeout: int = 900,
    ) -> dict:
        """Full WiFi password cracking pipeline: monitor mode, capture handshake,
        deauth clients, then crack with aircrack-ng.

        Args:
            interface: Wireless interface.
            bssid: Target AP BSSID (required).
            channel: AP channel (required).
            wordlist: Wordlist for cracking.
            capture_duration: Seconds to capture. Default 30.
            timeout: Max total seconds.
        """
        results = {}

        mon_result = await run_command(["airmon-ng", "start", sanitize_arg(interface)], timeout=15)
        results["monitor_mode"] = mon_result
        mon_iface = sanitize_arg(interface) + "mon"

        cap_prefix = "/opt/uts-mcp/output/wifi_crack"
        capture_cmd = [
            "airodump-ng", mon_iface,
            "-c", str(int(channel)),
            "--bssid", sanitize_arg(bssid),
            "-w", cap_prefix,
        ]
        cap_result = await run_command(capture_cmd, timeout=capture_duration + 5)
        results["capture"] = cap_result

        deauth_result = await run_command([
            "aireplay-ng", "--deauth", "10",
            "-a", sanitize_arg(bssid),
            mon_iface,
        ], timeout=15)
        results["deauth"] = deauth_result

        crack_result = await run_command([
            "aircrack-ng",
            "-w", sanitize_arg(wordlist),
            "-b", sanitize_arg(bssid),
            cap_prefix + "-01.cap",
        ], timeout=timeout)
        results["crack"] = crack_result

        await run_command(["airmon-ng", "stop", mon_iface], timeout=10)

        return {
            "success": crack_result.get("success", False),
            "steps": results,
        }

    @mcp.tool()
    async def mdk4_attack(
        interface: str,
        attack_mode: str = "b",
        extra_args: str = "",
        timeout: int = 30,
    ) -> dict:
        """WiFi denial-of-service and exploitation using mdk4.

        Args:
            interface: Monitor-mode interface (e.g. wlan0mon).
            attack_mode: Attack mode — b (beacon flood), a (auth DoS), d (deauth), m (michael shutdown), p (probe). Default b.
            extra_args: Additional arguments.
            timeout: Duration in seconds.
        """
        cmd = ["mdk4", sanitize_arg(interface), sanitize_arg(attack_mode)]
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def asleap_crack(
        interface: str = "",
        pcap_file: str = "",
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        timeout: int = 120,
    ) -> dict:
        """Crack LEAP/PPTP passwords using asleap.

        Args:
            interface: Capture interface. Empty if using pcap.
            pcap_file: Path to pcap file with LEAP exchanges.
            wordlist: Wordlist path.
            timeout: Max seconds.
        """
        cmd = ["asleap", "-W", sanitize_arg(wordlist)]
        if pcap_file:
            cmd.extend(["-r", sanitize_arg(pcap_file)])
        elif interface:
            cmd.extend(["-i", sanitize_arg(interface)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def spooftooph_spoof(
        interface: str = "hci0",
        name: str = "",
        address: str = "",
        timeout: int = 10,
    ) -> dict:
        """Spoof Bluetooth device name and address using SpoofTooph.

        Args:
            interface: Bluetooth interface. Default hci0.
            name: New device name to spoof.
            address: New Bluetooth address to spoof.
            timeout: Max seconds.
        """
        cmd = ["spooftooph", "-i", sanitize_arg(interface)]
        if name:
            cmd.extend(["-n", sanitize_arg(name)])
        if address:
            cmd.extend(["-a", sanitize_arg(address)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def hostapd_rogue_ap(
        config_file: str = "",
        ssid: str = "FreeWiFi",
        interface: str = "wlan0",
        channel: int = 6,
        timeout: int = 30,
    ) -> dict:
        """Create a rogue access point using hostapd/hostapd-wpe.

        Args:
            config_file: Path to hostapd config. Empty = auto-generate minimal config.
            ssid: SSID to broadcast. Default "FreeWiFi".
            interface: Wireless interface. Default wlan0.
            channel: WiFi channel. Default 6.
            timeout: Duration in seconds.
        """
        if not config_file:
            config_content = (
                f"interface={sanitize_arg(interface)}\n"
                f"ssid={sanitize_arg(ssid)}\n"
                f"channel={int(channel)}\n"
                "driver=nl80211\n"
                "hw_mode=g\n"
            )
            config_file = "/tmp/hostapd_rogue.conf"
            from pathlib import Path
            Path(config_file).write_text(config_content)
        cmd = ["hostapd", sanitize_arg(config_file)]
        return await run_command(cmd, timeout=timeout)
