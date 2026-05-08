"""Password cracking and brute-force tools: hydra, john, hashcat, medusa, ncrack,
patator, crowbar, brutespray, cewl, crunch, cupp."""

from tools.helpers import run_command, validate_target, sanitize_arg


def register_bruteforce_tools(mcp):

    @mcp.tool()
    async def hydra_attack(
        target: str,
        service: str,
        username: str = "",
        user_list: str = "",
        password: str = "",
        pass_list: str = "",
        port: int = 0,
        extra_args: str = "",
        timeout: int = 600,
    ) -> dict:
        """Run Hydra brute-force attack against a network service.

        Args:
            target: Target IP or hostname.
            service: Service protocol (ssh, ftp, http-get, http-post-form, smtp, etc.).
            username: Single username to test.
            user_list: Path to username wordlist file.
            password: Single password to test.
            pass_list: Path to password wordlist file.
            port: Service port (0 = default for service).
            extra_args: Additional hydra arguments.
            timeout: Max seconds. Default 600.
        """
        target = validate_target(target)
        cmd = ["hydra"]
        if username:
            cmd.extend(["-l", sanitize_arg(username)])
        elif user_list:
            cmd.extend(["-L", sanitize_arg(user_list)])
        if password:
            cmd.extend(["-p", sanitize_arg(password)])
        elif pass_list:
            cmd.extend(["-P", sanitize_arg(pass_list)])
        if port > 0:
            cmd.extend(["-s", str(int(port))])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        cmd.extend([target, sanitize_arg(service)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def john_crack(
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format: str = "",
        rules: str = "",
        timeout: int = 600,
    ) -> dict:
        """Crack password hashes using John the Ripper.

        Args:
            hash_file: Path to file containing hashes.
            wordlist: Wordlist path. Default: rockyou.txt.
            format: Hash format (e.g. raw-md5, sha256crypt). Empty = auto-detect.
            rules: Rules to apply (e.g. "best64", "jumbo").
            timeout: Max seconds.
        """
        cmd = ["john", "--wordlist=" + sanitize_arg(wordlist)]
        if format:
            cmd.append("--format=" + sanitize_arg(format))
        if rules:
            cmd.append("--rules=" + sanitize_arg(rules))
        cmd.append(sanitize_arg(hash_file))
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def john_show(hash_file: str, format: str = "") -> dict:
        """Show already-cracked passwords from John the Ripper's pot file.

        Args:
            hash_file: Path to hash file used in cracking.
            format: Hash format if needed.
        """
        cmd = ["john", "--show"]
        if format:
            cmd.append("--format=" + sanitize_arg(format))
        cmd.append(sanitize_arg(hash_file))
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def hashcat_crack(
        hash_file: str,
        hash_mode: int = 0,
        attack_mode: int = 0,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        rules: str = "",
        extra_args: str = "",
        timeout: int = 600,
    ) -> dict:
        """Crack hashes using Hashcat (CPU mode in Docker).

        Args:
            hash_file: Path to hash file.
            hash_mode: Hashcat hash mode number (0=MD5, 100=SHA1, 1000=NTLM, etc.).
            attack_mode: Attack mode (0=wordlist, 1=combination, 3=brute-force, 6=hybrid).
            wordlist: Wordlist path for dictionary attacks.
            rules: Rules file path.
            extra_args: Additional hashcat arguments.
            timeout: Max seconds.
        """
        cmd = [
            "hashcat",
            "-m", str(int(hash_mode)),
            "-a", str(int(attack_mode)),
            "--force",
            sanitize_arg(hash_file),
        ]
        if attack_mode in (0, 1, 6, 7):
            cmd.append(sanitize_arg(wordlist))
        if rules:
            cmd.extend(["-r", sanitize_arg(rules)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def medusa_attack(
        target: str,
        module: str,
        username: str = "",
        user_list: str = "",
        pass_list: str = "/usr/share/wordlists/rockyou.txt",
        port: int = 0,
        timeout: int = 600,
    ) -> dict:
        """Parallel brute-force with Medusa.

        Args:
            target: Target host.
            module: Service module (ssh, ftp, http, etc.).
            username: Single username.
            user_list: Username list file.
            pass_list: Password list file.
            port: Service port (0 = default).
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["medusa", "-h", target, "-M", sanitize_arg(module)]
        if username:
            cmd.extend(["-u", sanitize_arg(username)])
        elif user_list:
            cmd.extend(["-U", sanitize_arg(user_list)])
        cmd.extend(["-P", sanitize_arg(pass_list)])
        if port > 0:
            cmd.extend(["-n", str(int(port))])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def ncrack_attack(
        target: str,
        service: str,
        user_list: str = "",
        pass_list: str = "/usr/share/wordlists/rockyou.txt",
        timeout: int = 600,
    ) -> dict:
        """High-speed network auth cracker using Ncrack.

        Args:
            target: Target host (can include port as host:port).
            service: Service (ssh, ftp, telnet, http, rdp, smb, etc.).
            user_list: Username list file.
            pass_list: Password list file.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = ["ncrack", "-p", sanitize_arg(service)]
        if user_list:
            cmd.extend(["-U", sanitize_arg(user_list)])
        cmd.extend(["-P", sanitize_arg(pass_list)])
        cmd.append(target)
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def patator_attack(
        module: str,
        options: str,
        timeout: int = 600,
    ) -> dict:
        """Multi-purpose brute-forcer using Patator.

        Args:
            module: Attack module (ssh_login, ftp_login, http_fuzz, smtp_login, etc.).
            options: Space-separated module options
                (e.g. "host=10.0.0.1 user=FILE0 password=FILE1 0=/users.txt 1=/pass.txt").
            timeout: Max seconds.
        """
        cmd = ["patator", sanitize_arg(module)]
        cmd.extend(sanitize_arg(options).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def crowbar_attack(
        target: str,
        service: str,
        username: str = "",
        user_list: str = "",
        pass_list: str = "",
        key_dir: str = "",
        port: int = 0,
        timeout: int = 600,
    ) -> dict:
        """Brute-force tool supporting SSH keys, RDP, VNC, and OpenVPN using Crowbar.

        Args:
            target: Target IP or CIDR.
            service: Service (rdp, sshkey, vnckey, openvpn).
            username: Single username.
            user_list: Username list file.
            pass_list: Password list file.
            key_dir: Directory of SSH keys (for sshkey service).
            port: Service port.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = ["crowbar", "-b", sanitize_arg(service), "-s", target]
        if username:
            cmd.extend(["-u", sanitize_arg(username)])
        elif user_list:
            cmd.extend(["-U", sanitize_arg(user_list)])
        if pass_list:
            cmd.extend(["-C", sanitize_arg(pass_list)])
        if key_dir:
            cmd.extend(["-k", sanitize_arg(key_dir)])
        if port > 0:
            cmd.extend(["-p", str(int(port))])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def brutespray_attack(
        nmap_xml: str,
        threads: int = 5,
        timeout: int = 600,
    ) -> dict:
        """Auto-brute-force services found by Nmap using BruteSpray.

        Args:
            nmap_xml: Path to Nmap XML output file (use nmap -oX).
            threads: Concurrent threads. Default 5.
            timeout: Max seconds.
        """
        cmd = [
            "brutespray",
            "-f", sanitize_arg(nmap_xml),
            "-t", str(int(threads)),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def cewl_generate(
        url: str,
        depth: int = 2,
        min_length: int = 6,
        output_file: str = "/opt/uts-mcp/output/cewl_wordlist.txt",
    ) -> dict:
        """Generate a custom wordlist by spidering a website using CeWL.

        Args:
            url: Target URL to spider.
            depth: Spider depth. Default 2.
            min_length: Minimum word length. Default 6.
            output_file: Output file path.
        """
        cmd = [
            "cewl", sanitize_arg(url),
            "-d", str(int(depth)),
            "-m", str(int(min_length)),
            "-w", sanitize_arg(output_file),
        ]
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def crunch_generate(
        min_len: int,
        max_len: int,
        charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
        pattern: str = "",
        output_file: str = "/opt/uts-mcp/output/crunch_wordlist.txt",
    ) -> dict:
        """Generate wordlists with Crunch based on character sets and patterns.

        Args:
            min_len: Minimum word length.
            max_len: Maximum word length.
            charset: Character set to use.
            pattern: Pattern with placeholders (@ = lowercase, , = uppercase, % = numbers, ^ = symbols).
            output_file: Output file path.
        """
        cmd = [
            "crunch",
            str(int(min_len)),
            str(int(max_len)),
            sanitize_arg(charset),
            "-o", sanitize_arg(output_file),
        ]
        if pattern:
            cmd.extend(["-t", sanitize_arg(pattern)])
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def cupp_generate(
        first_name: str = "",
        last_name: str = "",
        birthdate: str = "",
        partner_name: str = "",
        pet_name: str = "",
        keywords: str = "",
        output_file: str = "/opt/uts-mcp/output/cupp_wordlist.txt",
    ) -> dict:
        """Generate targeted password wordlists using CUPP (Common User Passwords Profiler).

        Args:
            first_name: Target's first name.
            last_name: Target's last name.
            birthdate: Target's birthdate (DDMMYYYY).
            partner_name: Partner's name.
            pet_name: Pet's name.
            keywords: Extra keywords comma-separated.
            output_file: Output file path.
        """
        input_data = "\n".join([
            sanitize_arg(first_name),
            sanitize_arg(last_name),
            "",  # nickname
            sanitize_arg(birthdate),
            sanitize_arg(partner_name),
            "",  # partner nickname
            "",  # partner birthdate
            "",  # child name
            "",  # child nickname
            "",  # child birthdate
            sanitize_arg(pet_name),
            "",  # company name
            "n",  # special chars
            "n",  # random numbers
            "n",  # leet mode
        ])
        cmd = ["cupp", "-i"]
        return await run_command(cmd, timeout=30)
