"""Database assessment tools: sqlmap, sqlninja, bbqsql, odat, oscanner, etc."""

from tools.helpers import run_command, validate_url, validate_target, sanitize_arg


def register_database_tools(mcp):

    @mcp.tool()
    async def sqlninja_attack(
        config_file: str,
        mode: str = "test",
        timeout: int = 300,
    ) -> dict:
        """SQL injection exploitation focused on Microsoft SQL Server using sqlninja.

        Args:
            config_file: Path to sqlninja config file.
            mode: Attack mode (test, fingerprint, bruteforce, escalation, upload, etc.).
            timeout: Max seconds.
        """
        cmd = ["sqlninja", "-m", sanitize_arg(mode), "-f", sanitize_arg(config_file)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def bbqsql_scan(
        url: str,
        method: str = "GET",
        parameter: str = "",
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Blind SQL injection exploitation using BBQSQL.

        Args:
            url: Target URL.
            method: HTTP method. Default GET.
            parameter: Injectable parameter name.
            extra_args: Additional bbqsql arguments.
            timeout: Max seconds.
        """
        url = validate_url(url)
        cmd = ["bbqsql", "-u", url]
        if method.upper() != "GET":
            cmd.extend(["-m", sanitize_arg(method).upper()])
        if parameter:
            cmd.extend(["-p", sanitize_arg(parameter)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def odat_scan(
        target: str,
        sid: str = "",
        port: int = 1521,
        module: str = "all",
        username: str = "",
        password: str = "",
        timeout: int = 300,
    ) -> dict:
        """Oracle Database Attacking Tool (ODAT) — enumerate and exploit Oracle DBs.

        Args:
            target: Target IP or hostname.
            sid: Oracle SID. Empty = attempt discovery.
            port: Oracle port. Default 1521.
            module: Module (all, sidguesser, passwordguesser, utlhttp, dbmsscheduler, etc.).
            username: Oracle username.
            password: Oracle password.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["odat", sanitize_arg(module), "-s", target, "-p", str(int(port))]
        if sid:
            cmd.extend(["-d", sanitize_arg(sid)])
        if username:
            cmd.extend(["-U", sanitize_arg(username)])
        if password:
            cmd.extend(["-P", sanitize_arg(password)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def oscanner_scan(
        target: str,
        port: int = 1521,
        timeout: int = 120,
    ) -> dict:
        """Oracle Scanner — find Oracle installations and SIDs using oscanner.

        Args:
            target: Target IP.
            port: Oracle port. Default 1521.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["oscanner", "-s", target, "-P", str(int(port))]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def sidguesser_scan(
        target: str,
        port: int = 1521,
        wordlist: str = "",
        timeout: int = 120,
    ) -> dict:
        """Guess Oracle SIDs using sidguesser.

        Args:
            target: Target IP.
            port: Oracle port. Default 1521.
            wordlist: Custom SID wordlist. Empty = default.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = ["sidguesser", "-i", target, "-p", str(int(port))]
        if wordlist:
            cmd.extend(["-d", sanitize_arg(wordlist)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def tnscmd_probe(
        target: str,
        port: int = 1521,
        command: str = "version",
    ) -> dict:
        """Probe Oracle TNS listener using tnscmd10g.

        Args:
            target: Target IP.
            port: Oracle port. Default 1521.
            command: TNS command (version, status, services). Default version.
        """
        target = validate_target(target)
        cmd = [
            "tnscmd10g", sanitize_arg(command),
            "-h", target,
            "-p", str(int(port)),
        ]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def dbpwaudit_scan(
        target: str,
        database_type: str,
        port: int = 0,
        username_list: str = "",
        password_list: str = "",
        timeout: int = 300,
    ) -> dict:
        """Audit database passwords using dbpwaudit.

        Args:
            target: Target IP.
            database_type: Database type (mysql, mssql, oracle, db2).
            port: Database port (0 = default for type).
            username_list: Username list file.
            password_list: Password list file.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = [
            "dbpwaudit",
            "-s", target,
            "-d", sanitize_arg(database_type),
        ]
        if port > 0:
            cmd.extend(["-p", str(int(port))])
        if username_list:
            cmd.extend(["-U", sanitize_arg(username_list)])
        if password_list:
            cmd.extend(["-P", sanitize_arg(password_list)])
        return await run_command(cmd, timeout=timeout)
