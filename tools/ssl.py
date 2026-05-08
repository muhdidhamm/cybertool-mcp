"""SSL/TLS & HTTPS security testing tools: openssl, sslscan, sslyze, testssl.sh,
certificate inspection, cipher enumeration, vulnerability checks (Heartbleed,
POODLE, BEAST, ROBOT, etc.), and Post-Quantum Cryptography (PQC) readiness."""

import json

from tools.helpers import run_command, validate_target, sanitize_arg, save_output


def register_ssl_tools(mcp):

    @mcp.tool()
    async def ssl_cert_info(
        target: str,
        port: int = 443,
    ) -> dict:
        """Retrieve and display the SSL/TLS certificate for a target using openssl.

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
        """
        target = validate_target(target)
        cmd = [
            "bash", "-c",
            f"echo | openssl s_client -connect {target}:{int(port)} -servername {target} 2>/dev/null "
            f"| openssl x509 -noout -text"
        ]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def ssl_cert_chain(
        target: str,
        port: int = 443,
    ) -> dict:
        """Display the full certificate chain for a target.

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
        """
        target = validate_target(target)
        cmd = [
            "bash", "-c",
            f"echo | openssl s_client -connect {target}:{int(port)} -servername {target} "
            f"-showcerts 2>/dev/null"
        ]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def ssl_cert_dates(
        target: str,
        port: int = 443,
    ) -> dict:
        """Check certificate validity dates (expiry check).

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
        """
        target = validate_target(target)
        cmd = [
            "bash", "-c",
            f"echo | openssl s_client -connect {target}:{int(port)} -servername {target} 2>/dev/null "
            f"| openssl x509 -noout -dates -subject -issuer -serial -fingerprint"
        ]
        return await run_command(cmd, timeout=15)

    @mcp.tool()
    async def ssl_cipher_enum(
        target: str,
        port: int = 443,
    ) -> dict:
        """Enumerate supported SSL/TLS ciphers on a target using Nmap.

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
        """
        target = validate_target(target)
        cmd = [
            "nmap", "--script", "ssl-enum-ciphers",
            "-p", str(int(port)),
            target,
        ]
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def ssl_heartbleed_check(
        target: str,
        port: int = 443,
    ) -> dict:
        """Check if a target is vulnerable to Heartbleed (CVE-2014-0160).

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
        """
        target = validate_target(target)
        cmd = [
            "nmap", "--script", "ssl-heartbleed",
            "-p", str(int(port)),
            target,
        ]
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def ssl_poodle_check(
        target: str,
        port: int = 443,
    ) -> dict:
        """Check if a target is vulnerable to POODLE (SSLv3 fallback attack).

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
        """
        target = validate_target(target)
        cmd = [
            "nmap", "--script", "ssl-poodle",
            "-p", str(int(port)),
            target,
        ]
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def ssl_vuln_scan(
        target: str,
        port: int = 443,
        timeout: int = 300,
    ) -> dict:
        """Run all SSL/TLS vulnerability Nmap scripts against a target
        (Heartbleed, POODLE, CCS injection, DROWN, ROBOT, etc.).

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = [
            "nmap",
            "--script", "ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params,ssl-cert,ssl-enum-ciphers,ssl-known-key",
            "-p", str(int(port)),
            "-sV",
            target,
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def sslscan_full(
        target: str,
        port: int = 443,
        show_ciphers: bool = True,
        check_fallback: bool = True,
    ) -> dict:
        """Comprehensive SSL/TLS scan using sslscan.

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
            show_ciphers: Show supported ciphers. Default True.
            check_fallback: Check for TLS fallback. Default True.
        """
        target_str = sanitize_arg(target) + ":" + str(int(port))
        cmd = ["sslscan"]
        if not show_ciphers:
            cmd.append("--no-ciphersuites")
        if check_fallback:
            cmd.append("--no-colour")
        cmd.append(target_str)
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def sslyze_full(
        target: str,
        port: int = 443,
        certinfo: bool = True,
        heartbleed: bool = True,
        openssl_ccs: bool = True,
        robot: bool = True,
        timeout: int = 180,
    ) -> dict:
        """Deep SSL/TLS analysis using SSLyze with specific vulnerability checks.

        Args:
            target: Hostname.
            port: Port. Default 443.
            certinfo: Check certificate info. Default True.
            heartbleed: Check Heartbleed. Default True.
            openssl_ccs: Check OpenSSL CCS injection. Default True.
            robot: Check ROBOT vulnerability. Default True.
            timeout: Max seconds.
        """
        target_str = sanitize_arg(target) + ":" + str(int(port))
        cmd = ["sslyze"]
        if certinfo:
            cmd.append("--certinfo")
        if heartbleed:
            cmd.append("--heartbleed")
        if openssl_ccs:
            cmd.append("--openssl_ccs")
        if robot:
            cmd.append("--robot")
        cmd.append(target_str)
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def testssl_full(
        target: str,
        port: int = 443,
        checks: str = "",
        timeout: int = 600,
    ) -> dict:
        """Comprehensive SSL/TLS testing using testssl.sh — covers protocols,
        ciphers, vulnerabilities, and compliance.

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
            checks: Specific checks (e.g. "--heartbleed --robot --beast --crime --breach").
                    Empty = full scan.
            timeout: Max seconds.
        """
        target_str = sanitize_arg(target) + ":" + str(int(port))
        cmd = ["testssl", "--color", "0"]
        if checks:
            cmd.extend(sanitize_arg(checks).split())
        cmd.append(target_str)
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def ssl_protocol_test(
        target: str,
        port: int = 443,
        protocol: str = "tls1_2",
    ) -> dict:
        """Test if a specific SSL/TLS protocol version is supported.

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
            protocol: Protocol to test (ssl3, tls1, tls1_1, tls1_2, tls1_3). Default tls1_2.
        """
        target = validate_target(target)
        proto_flag = "-" + sanitize_arg(protocol)
        cmd = [
            "bash", "-c",
            f"echo | openssl s_client {proto_flag} -connect {target}:{int(port)} "
            f"-servername {target} 2>&1 | head -20"
        ]
        return await run_command(cmd, timeout=15)

    @mcp.tool()
    async def ssl_hsts_check(
        target: str,
        port: int = 443,
    ) -> dict:
        """Check if HTTP Strict Transport Security (HSTS) is enabled.

        Args:
            target: Hostname.
            port: Port. Default 443.
        """
        target = validate_target(target)
        cmd = [
            "curl", "-sI",
            f"https://{target}:{int(port)}/",
            "--max-time", "10",
            "-k",
        ]
        return await run_command(cmd, timeout=15)

    @mcp.tool()
    async def ssl_security_headers(
        url: str,
        timeout: int = 15,
    ) -> dict:
        """Check HTTP security headers on an HTTPS site (HSTS, CSP, X-Frame-Options,
        X-Content-Type-Options, Referrer-Policy, Permissions-Policy, etc.).

        Args:
            url: Full HTTPS URL.
            timeout: Max seconds.
        """
        url = sanitize_arg(url)
        cmd = [
            "curl", "-sI", "-L", "--max-time", str(int(timeout)), "-k", url,
        ]
        return await run_command(cmd, timeout=timeout + 5)

    @mcp.tool()
    async def openssl_connect(
        target: str,
        port: int = 443,
        starttls: str = "",
        extra_args: str = "",
    ) -> dict:
        """Raw openssl s_client connection for debugging SSL/TLS.

        Args:
            target: Hostname or IP.
            port: Port. Default 443.
            starttls: STARTTLS protocol (smtp, ftp, imap, pop3, xmpp). Empty = direct TLS.
            extra_args: Additional openssl s_client args.
        """
        target = validate_target(target)
        cmd_str = f"echo | openssl s_client -connect {target}:{int(port)} -servername {target}"
        if starttls:
            cmd_str += f" -starttls {sanitize_arg(starttls)}"
        if extra_args:
            cmd_str += f" {sanitize_arg(extra_args)}"
        cmd_str += " 2>&1"
        cmd = ["bash", "-c", cmd_str]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def nikto_ssl_scan(
        target: str,
        port: int = 443,
        tuning: str = "",
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Run Nikto specifically against an HTTPS target with SSL enabled.

        Args:
            target: Hostname or IP of the HTTPS server.
            port: HTTPS port. Default 443.
            tuning: Nikto tuning string.
            extra_args: Additional nikto arguments.
            timeout: Max seconds.
        """
        target = sanitize_arg(target)
        cmd = ["nikto", "-h", target, "-p", str(int(port)), "-ssl"]
        if tuning:
            cmd.extend(["-Tuning", sanitize_arg(tuning)])
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def nmap_ssl_full(
        target: str,
        port: int = 443,
        timeout: int = 300,
    ) -> dict:
        """Run all Nmap SSL/TLS scripts for comprehensive assessment.

        Args:
            target: Hostname or IP.
            port: HTTPS port. Default 443.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = [
            "nmap",
            "--script", "+ssl-*",
            "-p", str(int(port)),
            "-sV",
            target,
        ]
        return await run_command(cmd, timeout=timeout)

    # ── Post-Quantum Cryptography (PQC) Tools ─────────────────────────────

    @mcp.tool()
    async def pqc_full_assessment(
        target: str,
        port: int = 443,
        timeout: int = 300,
    ) -> dict:
        """Run a comprehensive Post-Quantum Cryptography readiness assessment.

        Probes TLS 1.3 support, PQC hybrid key exchange groups (Kyber/ML-KEM),
        certificate signature quantum-vulnerability, and testssl.sh PQC findings.
        Returns a scored readiness report (0-100) with recommendations.

        Args:
            target: Hostname or IP.
            port: TLS port. Default 443.
            timeout: Max seconds for the full assessment.
        """
        target = validate_target(target)
        cmd = [
            "python3", "/opt/uts-mcp/scripts/pqc_scanner.py",
            target, str(int(port)), "--json",
        ]
        result = await run_command(cmd, timeout=timeout)
        if result["success"] and result.get("stdout"):
            try:
                parsed = json.loads(result["stdout"])
                filename = f"pqc_assessment_{target}_{int(port)}.json"
                path = save_output(filename, json.dumps(parsed, indent=2))
                result["parsed"] = parsed
                result["report_file"] = path
            except json.JSONDecodeError:
                pass
        return result

    @mcp.tool()
    async def pqc_kex_probe(
        target: str,
        port: int = 443,
        groups: str = "",
        timeout: int = 120,
    ) -> dict:
        """Probe a server for PQC / hybrid key exchange group support via openssl.

        Tests whether the server accepts TLS 1.3 connections with specific
        post-quantum key exchange groups (e.g. X25519Kyber768, ML-KEM).

        Args:
            target: Hostname or IP.
            port: TLS port. Default 443.
            groups: Comma-separated groups to test. Default tests all known PQC groups.
            timeout: Max seconds.
        """
        target = validate_target(target)
        default_groups = [
            "x25519_kyber768", "X25519Kyber768Draft00", "x25519_mlkem768",
            "secp256r1_mlkem768", "secp384r1_mlkem1024",
            "kyber512", "kyber768", "kyber1024",
            "mlkem512", "mlkem768", "mlkem1024",
        ]
        test_groups = [sanitize_arg(g.strip()) for g in groups.split(",") if g.strip()] if groups else default_groups
        results = {"target": f"{target}:{port}", "groups_tested": len(test_groups), "supported": [], "unsupported": []}

        for group in test_groups:
            cmd = [
                "bash", "-c",
                f"echo | openssl s_client -connect {target}:{int(port)} "
                f"-servername {target} -tls1_3 -groups {group} 2>&1 | head -30",
            ]
            r = await run_command(cmd, timeout=15)
            stdout = r.get("stdout", "")
            if "Server Temp Key" in stdout and "error" not in stdout.lower():
                results["supported"].append(group)
            else:
                results["unsupported"].append(group)

        results["pqc_ready"] = len(results["supported"]) > 0
        return results

    @mcp.tool()
    async def pqc_cert_check(
        target: str,
        port: int = 443,
    ) -> dict:
        """Analyse a TLS certificate for post-quantum signature algorithms.

        Checks whether the certificate uses quantum-vulnerable classical
        algorithms (RSA, ECDSA, Ed25519) or PQC algorithms (ML-DSA/Dilithium,
        Falcon, SLH-DSA/SPHINCS+). Reports risk level and migration advice.

        Args:
            target: Hostname or IP.
            port: TLS port. Default 443.
        """
        target = validate_target(target)
        cmd = [
            "bash", "-c",
            f"echo | openssl s_client -connect {target}:{int(port)} "
            f"-servername {target} 2>/dev/null | "
            f"openssl x509 -noout -text 2>/dev/null | "
            f"grep -iE 'Signature Algorithm|Public Key Algorithm|Public-Key|Subject:|Issuer:'",
        ]
        r = await run_command(cmd, timeout=20)
        stdout = r.get("stdout", "")

        analysis = {
            "target": f"{target}:{port}",
            "quantum_vulnerable": True,
            "pqc_signature": False,
            "findings": [],
            "raw": stdout,
        }

        pqc_sigs = [
            "dilithium", "mldsa", "ml-dsa", "falcon", "sphincs",
            "slh-dsa", "xmss", "lms", "hss",
        ]
        classical_vuln = {
            "rsa": "Shor's algorithm breaks RSA key exchange and signatures",
            "ecdsa": "Shor's algorithm breaks elliptic curve discrete log",
            "ed25519": "Shor's algorithm breaks curve25519",
            "ed448": "Shor's algorithm breaks curve448",
            "dsa": "Shor's algorithm breaks discrete logarithm problem",
        }

        lower_out = stdout.lower()
        for pqc in pqc_sigs:
            if pqc in lower_out:
                analysis["pqc_signature"] = True
                analysis["quantum_vulnerable"] = False
                analysis["findings"].append(f"PQC signature algorithm detected: {pqc}")

        if not analysis["pqc_signature"]:
            for alg, reason in classical_vuln.items():
                if alg in lower_out:
                    analysis["findings"].append(f"QUANTUM-VULNERABLE: {alg} — {reason}")
            analysis["recommendations"] = [
                "Certificate uses classical cryptography vulnerable to quantum attacks",
                "Plan migration to ML-DSA (Dilithium) for signatures",
                "Use hybrid certificates during transition period",
                "Monitor CA providers for PQC certificate issuance support",
            ]

        return analysis

    @mcp.tool()
    async def pqc_tls13_groups(
        target: str,
        port: int = 443,
    ) -> dict:
        """List all TLS 1.3 supported groups (key exchange) on a server,
        highlighting any PQC or hybrid groups.

        Args:
            target: Hostname or IP.
            port: TLS port. Default 443.
        """
        target = validate_target(target)
        cmd = [
            "bash", "-c",
            f"echo | openssl s_client -connect {target}:{int(port)} "
            f"-servername {target} -tls1_3 2>&1",
        ]
        r = await run_command(cmd, timeout=15)
        stdout = r.get("stdout", "")

        pqc_keywords = [
            "kyber", "mlkem", "ml-kem", "x25519kyber", "x25519_kyber",
            "x25519_mlkem", "secp256r1_mlkem", "secp384r1_mlkem",
        ]

        groups_info = {"tls13_connection": "TLSv1.3" in stdout}
        import re
        group_match = re.search(r"Server Temp Key:\s*(.+)", stdout)
        if group_match:
            group = group_match.group(1).strip()
            groups_info["negotiated_group"] = group
            groups_info["is_pqc"] = any(kw in group.lower() for kw in pqc_keywords)
        else:
            groups_info["negotiated_group"] = None
            groups_info["is_pqc"] = False

        groups_info["raw_connection_info"] = stdout[:2000]
        return groups_info

    @mcp.tool()
    async def testssl_pqc(
        target: str,
        port: int = 443,
        timeout: int = 300,
    ) -> dict:
        """Run testssl.sh focused on PQC-related protocol and cipher findings.

        Checks TLS protocols, server preferences, and server defaults,
        then filters output for any post-quantum cryptography indicators.

        Args:
            target: Hostname or IP.
            port: TLS port. Default 443.
            timeout: Max seconds.
        """
        target = validate_target(target)
        target_str = f"{target}:{int(port)}"
        cmd = [
            "testssl", "--color", "0", "--protocols", "--server-preference",
            "--server-defaults", "--std", target_str,
        ]
        r = await run_command(cmd, timeout=timeout)
        stdout = r.get("stdout", "")

        pqc_keywords = [
            "kyber", "mlkem", "ml-kem", "dilithium", "mldsa", "ml-dsa",
            "falcon", "sphincs", "slh-dsa", "post-quantum", "hybrid",
            "x25519kyber", "x25519_kyber", "x25519_mlkem",
        ]
        pqc_findings = []
        for line in stdout.split("\n"):
            for kw in pqc_keywords:
                if kw in line.lower():
                    pqc_findings.append(line.strip())
                    break

        r["pqc_findings"] = pqc_findings
        r["pqc_detected"] = len(pqc_findings) > 0
        return r

    @mcp.tool()
    async def sslyze_pqc(
        target: str,
        port: int = 443,
        timeout: int = 180,
    ) -> dict:
        """Run SSLyze against a target and filter for PQC indicators.

        SSLyze reports TLS 1.3 cipher suites and key exchange groups,
        allowing detection of PQC / hybrid algorithms.

        Args:
            target: Hostname or IP.
            port: TLS port. Default 443.
            timeout: Max seconds.
        """
        target_str = sanitize_arg(target) + ":" + str(int(port))
        cmd = ["sslyze", "--tlsv1_3", "--certinfo", target_str]
        r = await run_command(cmd, timeout=timeout)
        stdout = r.get("stdout", "")

        pqc_keywords = [
            "kyber", "mlkem", "ml-kem", "dilithium", "mldsa", "ml-dsa",
            "falcon", "sphincs", "slh-dsa", "post-quantum", "hybrid",
        ]
        pqc_lines = []
        for line in stdout.split("\n"):
            for kw in pqc_keywords:
                if kw in line.lower():
                    pqc_lines.append(line.strip())
                    break

        r["pqc_findings"] = pqc_lines
        r["pqc_detected"] = len(pqc_lines) > 0
        return r

    @mcp.tool()
    async def pqc_quantum_risk_summary(
        target: str,
        port: int = 443,
        timeout: int = 60,
    ) -> dict:
        """Quick quantum-risk summary for a TLS endpoint.

        Rapidly checks TLS version, key exchange, and certificate
        signature to produce a risk rating and migration checklist.

        Args:
            target: Hostname or IP.
            port: TLS port. Default 443.
            timeout: Max seconds.
        """
        target = validate_target(target)
        cmd = [
            "bash", "-c",
            f"echo | openssl s_client -connect {target}:{int(port)} "
            f"-servername {target} -brief 2>&1",
        ]
        brief = await run_command(cmd, timeout=15)
        brief_out = brief.get("stdout", "")

        cmd2 = [
            "bash", "-c",
            f"echo | openssl s_client -connect {target}:{int(port)} "
            f"-servername {target} 2>/dev/null | "
            f"openssl x509 -noout -subject -issuer -dates "
            f"-pubkey -text 2>/dev/null | "
            f"grep -iE 'Signature Algorithm|Public.Key|Subject:|Issuer:|Not |Public-Key'",
        ]
        cert = await run_command(cmd2, timeout=15)
        cert_out = cert.get("stdout", "")
        combined = (brief_out + cert_out).lower()

        risk = {
            "target": f"{target}:{port}",
            "tls13": "tlsv1.3" in combined,
            "pqc_kex": False,
            "pqc_cert": False,
            "classical_kex": None,
            "classical_sig": None,
            "risk_level": "CRITICAL",
            "harvest_now_decrypt_later": True,
            "migration_checklist": [],
        }

        pqc_kex_kw = ["kyber", "mlkem", "ml-kem"]
        pqc_sig_kw = ["dilithium", "mldsa", "ml-dsa", "falcon", "sphincs", "slh-dsa"]

        for kw in pqc_kex_kw:
            if kw in combined:
                risk["pqc_kex"] = True
                break
        for kw in pqc_sig_kw:
            if kw in combined:
                risk["pqc_cert"] = True
                break

        import re
        tk_match = re.search(r"server temp key:\s*(.+)", combined)
        if tk_match:
            risk["classical_kex"] = tk_match.group(1).strip()
        sig_match = re.search(r"signature algorithm:\s*(\S+)", combined)
        if sig_match:
            risk["classical_sig"] = sig_match.group(1).strip()

        if risk["pqc_kex"] and risk["pqc_cert"]:
            risk["risk_level"] = "LOW"
            risk["harvest_now_decrypt_later"] = False
        elif risk["pqc_kex"]:
            risk["risk_level"] = "MEDIUM"
            risk["harvest_now_decrypt_later"] = False
        elif risk["tls13"]:
            risk["risk_level"] = "HIGH"
        else:
            risk["risk_level"] = "CRITICAL"

        if not risk["tls13"]:
            risk["migration_checklist"].append("Enable TLS 1.3 (required for PQC key exchange)")
        if not risk["pqc_kex"]:
            risk["migration_checklist"].append("Deploy hybrid key exchange (X25519Kyber768 / X25519_MLKEM768)")
        if not risk["pqc_cert"]:
            risk["migration_checklist"].append("Plan migration to PQC certificate (ML-DSA/Dilithium)")
        risk["migration_checklist"].extend([
            "Inventory all TLS endpoints for quantum-vulnerability",
            "Prioritise endpoints handling sensitive/long-lived data",
            "Test PQC with Chrome/Edge (support X25519Kyber768 since 2024)",
            "Monitor NIST PQC standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)",
        ])
        return risk
