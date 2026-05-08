"""Active Directory, Windows, and lateral movement tools: impacket, crackmapexec,
netexec, responder, bloodhound, smbclient, smbmap, rpcclient, evil-winrm,
certipy, kerbrute, ldapdomaindump."""

from tools.helpers import run_command, validate_target, sanitize_arg


def register_ad_tools(mcp):

    @mcp.tool()
    async def crackmapexec_scan(
        target: str,
        protocol: str = "smb",
        username: str = "",
        password: str = "",
        domain: str = "",
        module: str = "",
        extra_args: str = "",
        timeout: int = 120,
    ) -> dict:
        """Swiss army knife for pentesting Windows/AD networks using CrackMapExec.

        Args:
            target: Target IP, CIDR, or hostname.
            protocol: Protocol (smb, winrm, ldap, mssql, ssh, rdp). Default smb.
            username: Username for authentication.
            password: Password for authentication.
            domain: AD domain name.
            module: CrackMapExec module to run (e.g. "spider_plus", "mimikatz").
            extra_args: Additional arguments.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = ["crackmapexec", sanitize_arg(protocol), target]
        if username:
            cmd.extend(["-u", sanitize_arg(username)])
        if password:
            cmd.extend(["-p", sanitize_arg(password)])
        if domain:
            cmd.extend(["-d", sanitize_arg(domain)])
        if module:
            cmd.extend(["-M", sanitize_arg(module)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def impacket_secretsdump(
        target: str,
        username: str,
        password: str = "",
        hashes: str = "",
        domain: str = "",
        timeout: int = 120,
    ) -> dict:
        """Dump secrets (SAM, LSA, NTDS.DIT) from Windows hosts using impacket-secretsdump.

        Args:
            target: Target IP or hostname.
            username: Username.
            password: Password.
            hashes: NTLM hash (LM:NT format) for pass-the-hash.
            domain: AD domain.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cred = sanitize_arg(domain) + "/" if domain else ""
        cred += sanitize_arg(username)
        if password:
            cred += ":" + sanitize_arg(password)

        cmd = ["impacket-secretsdump", cred + "@" + target]
        if hashes:
            cmd.extend(["-hashes", sanitize_arg(hashes)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def impacket_psexec(
        target: str,
        username: str,
        password: str = "",
        hashes: str = "",
        domain: str = "",
        command: str = "whoami",
        timeout: int = 60,
    ) -> dict:
        """Remote command execution via PsExec using impacket-psexec.

        Args:
            target: Target IP or hostname.
            username: Username.
            password: Password.
            hashes: NTLM hash for pass-the-hash.
            domain: AD domain.
            command: Command to execute. Default "whoami".
            timeout: Max seconds.
        """
        target = validate_target(target)
        cred = sanitize_arg(domain) + "/" if domain else ""
        cred += sanitize_arg(username)
        if password:
            cred += ":" + sanitize_arg(password)

        cmd = ["impacket-psexec", cred + "@" + target, sanitize_arg(command)]
        if hashes:
            cmd.extend(["-hashes", sanitize_arg(hashes)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def impacket_smbclient(
        target: str,
        username: str = "guest",
        password: str = "",
        domain: str = "",
        timeout: int = 30,
    ) -> dict:
        """Interactive SMB client using impacket-smbclient (list shares).

        Args:
            target: Target IP or hostname.
            username: Username. Default guest.
            password: Password.
            domain: AD domain.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cred = sanitize_arg(domain) + "/" if domain else ""
        cred += sanitize_arg(username)
        if password:
            cred += ":" + sanitize_arg(password)
        cmd = ["impacket-smbclient", cred + "@" + target, "-c", "shares"]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def impacket_wmiexec(
        target: str,
        username: str,
        password: str = "",
        hashes: str = "",
        domain: str = "",
        command: str = "whoami",
        timeout: int = 60,
    ) -> dict:
        """Remote command execution via WMI using impacket-wmiexec.

        Args:
            target: Target IP or hostname.
            username: Username.
            password: Password.
            hashes: NTLM hash for pass-the-hash.
            domain: AD domain.
            command: Command to execute.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cred = sanitize_arg(domain) + "/" if domain else ""
        cred += sanitize_arg(username)
        if password:
            cred += ":" + sanitize_arg(password)

        cmd = ["impacket-wmiexec", cred + "@" + target, sanitize_arg(command)]
        if hashes:
            cmd.extend(["-hashes", sanitize_arg(hashes)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def smbclient_list(
        target: str,
        username: str = "",
        password: str = "",
    ) -> dict:
        """List SMB shares on a target using smbclient.

        Args:
            target: Target IP or hostname.
            username: Username. Empty = anonymous.
            password: Password.
        """
        target = validate_target(target)
        cmd = ["smbclient", "-L", target, "-N"]
        if username:
            cmd.extend(["-U", sanitize_arg(username)])
            if password:
                cmd[-1] += "%" + sanitize_arg(password)
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def responder_listen(
        interface: str = "eth0",
        analyze_only: bool = True,
        timeout: int = 60,
    ) -> dict:
        """Capture NTLM hashes using Responder (LLMNR/NBT-NS/mDNS poisoner).

        Args:
            interface: Network interface. Default eth0.
            analyze_only: Analyze mode only (no poisoning). Default True for safety.
            timeout: Capture duration in seconds.
        """
        cmd = ["responder", "-I", sanitize_arg(interface)]
        if analyze_only:
            cmd.append("-A")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def kerbrute_userenum(
        domain: str,
        dc: str,
        user_list: str,
        timeout: int = 120,
    ) -> dict:
        """Enumerate valid Active Directory usernames via Kerberos using Kerbrute.

        Args:
            domain: AD domain name.
            dc: Domain controller IP or hostname.
            user_list: Path to username list file.
            timeout: Max seconds.
        """
        dc = validate_target(dc)
        cmd = [
            "kerbrute", "userenum",
            "--dc", dc,
            "-d", sanitize_arg(domain),
            sanitize_arg(user_list),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def kerbrute_passwordspray(
        domain: str,
        dc: str,
        user_list: str,
        password: str,
        timeout: int = 120,
    ) -> dict:
        """Password spray against AD accounts via Kerberos using Kerbrute.

        Args:
            domain: AD domain name.
            dc: Domain controller IP.
            user_list: Path to username list file.
            password: Password to spray.
            timeout: Max seconds.
        """
        dc = validate_target(dc)
        cmd = [
            "kerbrute", "passwordspray",
            "--dc", dc,
            "-d", sanitize_arg(domain),
            sanitize_arg(user_list),
            sanitize_arg(password),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def ldapdomaindump_dump(
        target: str,
        username: str,
        password: str,
        domain: str = "",
        output_dir: str = "/opt/uts-mcp/output/ldap_dump",
        timeout: int = 120,
    ) -> dict:
        """Dump Active Directory info via LDAP using ldapdomaindump.

        Args:
            target: Domain controller IP or hostname.
            username: Username.
            password: Password.
            domain: AD domain. Empty = auto-detect.
            output_dir: Output directory.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cred = sanitize_arg(domain) + "\\\\" if domain else ""
        cred += sanitize_arg(username)
        cmd = [
            "ldapdomaindump", target,
            "-u", cred,
            "-p", sanitize_arg(password),
            "-o", sanitize_arg(output_dir),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def bloodhound_collect(
        domain: str,
        dc: str,
        username: str,
        password: str,
        collection: str = "all",
        timeout: int = 300,
    ) -> dict:
        """Collect Active Directory data for BloodHound using bloodhound-python.

        Args:
            domain: AD domain.
            dc: Domain controller hostname.
            username: Username.
            password: Password.
            collection: Collection method (all, group, localadmin, session, trusts, etc.). Default all.
            timeout: Max seconds.
        """
        dc = validate_target(dc)
        cmd = [
            "bloodhound-python",
            "-d", sanitize_arg(domain),
            "-u", sanitize_arg(username),
            "-p", sanitize_arg(password),
            "-ns", dc,
            "-c", sanitize_arg(collection),
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def impacket_getnpusers(
        domain: str,
        dc: str,
        user_list: str = "",
        username: str = "",
        timeout: int = 60,
    ) -> dict:
        """Find AS-REP roastable accounts using impacket-GetNPUsers.

        Args:
            domain: AD domain.
            dc: Domain controller IP.
            user_list: File with usernames.
            username: Single username.
            timeout: Max seconds.
        """
        dc = validate_target(dc)
        target_str = sanitize_arg(domain) + "/"
        if username:
            target_str += sanitize_arg(username)

        cmd = ["impacket-GetNPUsers", target_str, "-dc-ip", dc, "-no-pass"]
        if user_list:
            cmd.extend(["-usersfile", sanitize_arg(user_list)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def impacket_getuserspns(
        domain: str,
        dc: str,
        username: str,
        password: str,
        timeout: int = 60,
    ) -> dict:
        """Kerberoast — request service tickets for cracking using impacket-GetUserSPNs.

        Args:
            domain: AD domain.
            dc: Domain controller IP.
            username: Username with valid credentials.
            password: Password.
            timeout: Max seconds.
        """
        dc = validate_target(dc)
        cred = sanitize_arg(domain) + "/" + sanitize_arg(username) + ":" + sanitize_arg(password)
        cmd = ["impacket-GetUserSPNs", cred, "-dc-ip", dc, "-request"]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def netexec_scan(
        target: str,
        protocol: str = "smb",
        username: str = "",
        password: str = "",
        domain: str = "",
        module: str = "",
        extra_args: str = "",
        timeout: int = 120,
    ) -> dict:
        """Network-wide assessment with NetExec (successor to CrackMapExec).

        Args:
            target: Target IP, CIDR, or hostname.
            protocol: Protocol (smb, winrm, ldap, mssql, ssh, rdp, wmi, vnc, ftp). Default smb.
            username: Username for authentication.
            password: Password for authentication.
            domain: AD domain name.
            module: Module to run (e.g. "spider_plus", "enum_av").
            extra_args: Additional arguments.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = ["netexec", sanitize_arg(protocol), target]
        if username:
            cmd.extend(["-u", sanitize_arg(username)])
        if password:
            cmd.extend(["-p", sanitize_arg(password)])
        if domain:
            cmd.extend(["-d", sanitize_arg(domain)])
        if module:
            cmd.extend(["-M", sanitize_arg(module)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def smbmap_scan(
        target: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        recurse: bool = False,
        timeout: int = 60,
    ) -> dict:
        """Enumerate SMB shares and permissions using smbmap.

        Args:
            target: Target IP or hostname.
            username: Username. Empty = null session.
            password: Password.
            domain: AD domain.
            recurse: Recursively list share contents. Default False.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["smbmap", "-H", target]
        if username:
            cmd.extend(["-u", sanitize_arg(username)])
        if password:
            cmd.extend(["-p", sanitize_arg(password)])
        if domain:
            cmd.extend(["-d", sanitize_arg(domain)])
        if recurse:
            cmd.append("-R")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def rpcclient_enum(
        target: str,
        username: str = "",
        password: str = "",
        rpc_command: str = "enumdomusers",
        timeout: int = 30,
    ) -> dict:
        """Interact with Windows RPC interfaces using rpcclient.

        Args:
            target: Target IP or hostname.
            username: Username. Empty = null session.
            password: Password.
            rpc_command: RPC command (enumdomusers, enumdomgroups, lookupnames, etc.).
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["rpcclient", target, "-c", sanitize_arg(rpc_command)]
        if username:
            cmd.extend(["-U", sanitize_arg(username) + ("%" + sanitize_arg(password) if password else "")])
        else:
            cmd.extend(["-U", "", "-N"])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def evil_winrm_exec(
        target: str,
        username: str,
        password: str = "",
        hash_val: str = "",
        command: str = "whoami",
        timeout: int = 60,
    ) -> dict:
        """Remote shell on Windows via WinRM using Evil-WinRM.

        Args:
            target: Target IP or hostname.
            username: Username.
            password: Password.
            hash_val: NTLM hash for pass-the-hash.
            command: Command to execute.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["evil-winrm", "-i", target, "-u", sanitize_arg(username)]
        if hash_val:
            cmd.extend(["-H", sanitize_arg(hash_val)])
        elif password:
            cmd.extend(["-p", sanitize_arg(password)])
        cmd.extend(["-c", sanitize_arg(command)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def certipy_find(
        target: str,
        username: str,
        password: str,
        domain: str = "",
        vulnerable: bool = True,
        timeout: int = 120,
    ) -> dict:
        """Find vulnerable AD Certificate Services (AD CS) templates using Certipy.

        Args:
            target: Domain controller IP or hostname.
            username: Username.
            password: Password.
            domain: AD domain.
            vulnerable: Only show vulnerable templates. Default True.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cred = sanitize_arg(username) + ":" + sanitize_arg(password)
        if domain:
            cred = sanitize_arg(domain) + "/" + cred
        cmd = ["certipy", "find", "-u", cred, "-dc-ip", target]
        if vulnerable:
            cmd.append("-vulnerable")
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def enum4linux_ng_scan(
        target: str,
        username: str = "",
        password: str = "",
        timeout: int = 120,
    ) -> dict:
        """Windows/Samba enumeration using enum4linux-ng (next-gen).

        Args:
            target: Target IP or hostname.
            username: Username. Empty = null session.
            password: Password.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["enum4linux-ng", "-A", target]
        if username:
            cmd.extend(["-u", sanitize_arg(username)])
        if password:
            cmd.extend(["-p", sanitize_arg(password)])
        return await run_command(cmd, timeout=timeout)
