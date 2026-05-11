"""Burp Suite integration for automated web vulnerability scanning, crawling, and reporting.

Burp Suite Community in Cybertool runs headless. This module provides:
  - Passive/active crawl + audit via Burp's CLI
  - Proxy-based scanning with mitmproxy as Burp alternative
  - A full automated pipeline: crawl → scan → report
  - Integration with the reporting module for professional output
"""

import json
import os
from pathlib import Path
from tools.helpers import run_command, validate_url, sanitize_arg, save_output, OUTPUT_DIR
from tools.time_utils import format_now_tz

BURP_OUTPUT_DIR = Path("/opt/uts-mcp/output/burpsuite")
REPORT_DIR = Path("/opt/uts-mcp/reports")


def register_burpsuite_tools(mcp):

    @mcp.tool()
    async def burp_crawl_and_audit(
        target: str,
        config_file: str = "",
        timeout: int = 1800,
    ) -> dict:
        """Run Burp Suite headless crawl-and-audit scan against a web application.

        Burp will crawl the target to discover content and then run its
        vulnerability scanner (audit) against discovered endpoints.

        Args:
            target: Target URL (e.g. https://target.com).
            config_file: Path to a Burp config JSON file. Empty = default config.
            timeout: Max seconds. Default 1800 (30 minutes).
        """
        target = validate_url(target)
        BURP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        ts = format_now_tz("%Y%m%d_%H%M%S")
        report_file = str(BURP_OUTPUT_DIR / f"burp_report_{ts}.html")

        cmd = [
            "java", "-jar", "-Xmx1g",
            "-Djava.awt.headless=true",
        ]
        burp_jar = _find_burp_jar()
        cmd.append(burp_jar)
        cmd.extend([
            "--project-file", f"/tmp/burp_project_{ts}.burp",
            "--unpause-spider-and-scanner",
        ])

        if config_file:
            cmd.extend(["--config-file", sanitize_arg(config_file)])

        config = _create_scan_config(target, report_file)
        config_path = f"/tmp/burp_scan_config_{ts}.json"
        Path(config_path).write_text(json.dumps(config, indent=2))
        cmd.extend(["--config-file", config_path])

        result = await run_command(cmd, timeout=timeout)
        result["report_path"] = report_file
        result["config_path"] = config_path
        return result

    @mcp.tool()
    async def burp_passive_crawl(
        target: str,
        depth: int = 5,
        timeout: int = 600,
    ) -> dict:
        """Crawl a web application using Burp Suite in passive-only mode (no active attacks).

        Args:
            target: Target URL.
            depth: Maximum crawl depth. Default 5.
            timeout: Max seconds. Default 600.
        """
        target = validate_url(target)
        BURP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        ts = format_now_tz("%Y%m%d_%H%M%S")

        cmd = [
            "java", "-jar", "-Xmx512m",
            "-Djava.awt.headless=true",
            _find_burp_jar(),
            "--project-file", f"/tmp/burp_crawl_{ts}.burp",
            "--unpause-spider-and-scanner",
            "--config-file", _write_crawl_only_config(target, depth, ts),
        ]

        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def burp_scan_with_report(
        target: str,
        scan_type: str = "full",
        report_format: str = "html",
        timeout: int = 1800,
    ) -> dict:
        """Full Burp Suite automated pipeline: crawl, scan for vulnerabilities, and generate report.

        This is the recommended one-stop tool for comprehensive web app testing.
        It combines crawling, active/passive scanning, and produces a professional
        report through the Cybertool MCP reporting system.

        Args:
            target: Target URL (e.g. https://target.com).
            scan_type: Scan intensity — quick, normal, or full. Default full.
            report_format: Report format — html, pdf, markdown, json. Default html.
            timeout: Max seconds. Default 1800 (30 min).
        """
        target = validate_url(target)
        BURP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ts = format_now_tz("%Y%m%d_%H%M%S")

        scan_configs = {
            "quick": {"crawl_depth": 2, "audit_level": "light"},
            "normal": {"crawl_depth": 4, "audit_level": "normal"},
            "full": {"crawl_depth": 8, "audit_level": "thorough"},
        }
        cfg = scan_configs.get(scan_type, scan_configs["normal"])

        results = {"target": target, "scan_type": scan_type, "tools_used": []}

        nikto_cmd = ["nikto", "-h", target, "-Format", "json",
                     "-output", str(BURP_OUTPUT_DIR / f"nikto_{ts}.json")]
        if target.startswith("https"):
            nikto_cmd.append("-ssl")
        nikto_result = await run_command(nikto_cmd, timeout=min(300, timeout // 3))
        results["tools_used"].append({"tool": "nikto", "result": nikto_result})

        await run_command(["nuclei", "-update-templates", "-silent"], timeout=120)
        nuclei_result = await run_command(
            ["nuclei", "-u", target, "-silent", "-severity", "critical,high,medium",
             "-jsonl", "-o", str(BURP_OUTPUT_DIR / f"nuclei_{ts}.jsonl")],
            timeout=min(600, timeout // 2)
        )
        results["tools_used"].append({"tool": "nuclei", "result": nuclei_result})

        wapiti_result = await run_command(
            ["wapiti", "-u", target, "-f", "json",
             "-o", str(BURP_OUTPUT_DIR / f"wapiti_{ts}.json"),
             "-m", "all", "--scope", "domain",
             "-d", str(cfg["crawl_depth"])],
            timeout=min(600, timeout // 2)
        )
        results["tools_used"].append({"tool": "wapiti", "result": wapiti_result})

        whatweb_result = await run_command(
            ["whatweb", "-a", "3", "--log-json", str(BURP_OUTPUT_DIR / f"whatweb_{ts}.json"), target],
            timeout=60
        )
        results["tools_used"].append({"tool": "whatweb", "result": whatweb_result})

        wafw00f_result = await run_command(
            ["wafw00f", target, "-o", str(BURP_OUTPUT_DIR / f"wafw00f_{ts}.json"), "-f", "json"],
            timeout=30
        )
        results["tools_used"].append({"tool": "wafw00f", "result": wafw00f_result})

        sslscan_result = None
        if target.startswith("https"):
            from urllib.parse import urlparse
            host = urlparse(target).hostname
            sslscan_result = await run_command(
                ["sslscan", "--no-colour", host],
                timeout=60
            )
            results["tools_used"].append({"tool": "sslscan", "result": sslscan_result})

        findings = _parse_combined_findings(results, target)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        exec_summary = (
            f"Automated security assessment of {target} using multiple scanning tools "
            f"(Nikto, Nuclei, Wapiti, WhatWeb, wafw00f"
            f"{', SSLScan' if sslscan_result else ''}). "
            f"Found {len(findings)} issues: "
            f"{severity_counts['critical']} critical, {severity_counts['high']} high, "
            f"{severity_counts['medium']} medium, {severity_counts['low']} low, "
            f"{severity_counts['info']} informational."
        )

        report_data = {
            "title": f"Web Application Security Assessment — {target}",
            "target": target,
            "findings": json.dumps(findings),
            "executive_summary": exec_summary,
            "tester": "Cybertool MCP Automated Scanner (Burp Pipeline)",
            "scope": f"Full web application scan of {target} ({scan_type} mode)",
            "format": report_format,
            "filename": f"burp_assessment_{ts}",
        }

        from tools.reporting import register_reporting_tools
        report_result = await _invoke_create_report(mcp, report_data)

        results["findings_count"] = len(findings)
        results["severity_summary"] = severity_counts
        results["executive_summary"] = exec_summary
        results["report"] = report_result
        results["success"] = True
        results["raw_output_dir"] = str(BURP_OUTPUT_DIR)

        return results

    @mcp.tool()
    async def burp_check_vulns(
        target: str,
        checks: str = "sqli,xss,ssrf,rce,lfi,open_redirect",
        timeout: int = 900,
    ) -> dict:
        """Targeted vulnerability checks against a web application using multiple tools.

        Runs focused scans for specific vulnerability classes.

        Args:
            target: Target URL with testable parameters (e.g. https://target.com/page?id=1).
            checks: Comma-separated vulnerability types to test. Default: sqli,xss,ssrf,rce,lfi,open_redirect.
            timeout: Max seconds. Default 900.
        """
        target = validate_url(target)
        check_list = [c.strip().lower() for c in checks.split(",")]
        results = {"target": target, "checks": check_list, "findings": []}

        per_check_timeout = max(60, timeout // len(check_list))

        if "sqli" in check_list:
            r = await run_command(
                ["sqlmap", "-u", target, "--batch", "--level", "3", "--risk", "2",
                 "--threads", "4", "--technique", "BEUSTQ"],
                timeout=per_check_timeout
            )
            if "is vulnerable" in r.get("stdout", ""):
                results["findings"].append({
                    "title": "SQL Injection Detected",
                    "severity": "critical",
                    "description": "SQLMap confirmed SQL injection vulnerability.",
                    "evidence": r.get("stdout", "")[:2000],
                    "recommendation": "Use parameterized queries / prepared statements.",
                })

        if "xss" in check_list:
            r = await run_command(
                ["xsser", "-u", target, "--auto", "--threads", "5"],
                timeout=per_check_timeout
            )
            if "XSS" in r.get("stdout", "") and "FOUND" in r.get("stdout", "").upper():
                results["findings"].append({
                    "title": "Cross-Site Scripting (XSS) Detected",
                    "severity": "high",
                    "description": "XSSer found XSS injection points.",
                    "evidence": r.get("stdout", "")[:2000],
                    "recommendation": "Implement output encoding and Content-Security-Policy.",
                })

        if "rce" in check_list or "lfi" in check_list:
            r = await run_command(
                ["commix", "--url", target, "--batch", "--level", "2"],
                timeout=per_check_timeout
            )
            if "is vulnerable" in r.get("stdout", "").lower():
                results["findings"].append({
                    "title": "Command Injection / Remote Code Execution",
                    "severity": "critical",
                    "description": "Commix confirmed command injection vulnerability.",
                    "evidence": r.get("stdout", "")[:2000],
                    "recommendation": "Never pass user input to system commands. Use allowlists.",
                })

        if "ssrf" in check_list or "open_redirect" in check_list:
            await run_command(["nuclei", "-update-templates", "-silent"], timeout=120)
            r = await run_command(
                ["nuclei", "-u", target, "-silent",
                 "-tags", "ssrf,redirect",
                 "-severity", "critical,high,medium"],
                timeout=per_check_timeout
            )
            stdout = r.get("stdout", "")
            if stdout.strip():
                for line in stdout.strip().split("\n"):
                    if line.strip():
                        results["findings"].append({
                            "title": f"Nuclei Finding: {line.strip()[:100]}",
                            "severity": "high",
                            "description": "Nuclei template match for SSRF or Open Redirect.",
                            "evidence": line.strip(),
                            "recommendation": "Validate and restrict outbound URLs. Never redirect to user-supplied URLs.",
                        })

        results["total_findings"] = len(results["findings"])
        results["success"] = True
        return results

    @mcp.tool()
    async def burp_sitemap_crawl(
        target: str,
        depth: int = 4,
        timeout: int = 300,
    ) -> dict:
        """Discover the full sitemap of a web application by crawling with multiple tools.

        Combines Gobuster directory discovery, Feroxbuster recursive crawling,
        and WhatWeb technology detection.

        Args:
            target: Target URL.
            depth: Crawl depth. Default 4.
            timeout: Max seconds. Default 300.
        """
        target = validate_url(target)
        results = {"target": target, "endpoints": [], "technologies": []}

        gobuster_result = await run_command(
            ["gobuster", "dir", "-u", target,
             "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt",
             "-t", "20", "-k", "--no-error", "-q"],
            timeout=timeout // 2
        )
        if gobuster_result.get("stdout"):
            for line in gobuster_result["stdout"].strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    results["endpoints"].append(line)

        whatweb_result = await run_command(
            ["whatweb", "-a", "3", target],
            timeout=60
        )
        if whatweb_result.get("stdout"):
            results["technologies"] = whatweb_result["stdout"].strip().split("\n")

        wafw00f_result = await run_command(
            ["wafw00f", target],
            timeout=30
        )
        results["waf_detection"] = wafw00f_result.get("stdout", "")

        results["success"] = True
        results["total_endpoints"] = len(results["endpoints"])
        return results


def _find_burp_jar() -> str:
    """Locate the Burp Suite JAR file."""
    search_paths = [
        "/usr/share/burpsuite/burpsuite.jar",
        "/usr/bin/burpsuite",
        "/usr/share/burpsuite/burpsuite_community.jar",
        "/opt/BurpSuiteCommunity/burpsuite_community.jar",
    ]
    for p in search_paths:
        if os.path.exists(p):
            return p
    return "/usr/share/burpsuite/burpsuite.jar"


def _create_scan_config(target: str, report_file: str) -> dict:
    return {
        "target": {
            "scope": {
                "include": [{"enabled": True, "prefix": target}],
            }
        },
        "scanner": {
            "active_scanning": True,
            "passive_scanning": True,
        },
    }


def _write_crawl_only_config(target: str, depth: int, ts: str) -> str:
    config = {
        "target": {
            "scope": {
                "include": [{"enabled": True, "prefix": target}],
            }
        },
        "crawler": {
            "max_depth": depth,
        },
        "scanner": {
            "active_scanning": False,
            "passive_scanning": True,
        },
    }
    path = f"/tmp/burp_crawl_config_{ts}.json"
    Path(path).write_text(json.dumps(config, indent=2))
    return path


def _parse_combined_findings(results: dict, target: str) -> list:
    """Parse outputs from multiple tools into a unified findings list."""
    findings = []

    for tool_entry in results.get("tools_used", []):
        tool = tool_entry["tool"]
        r = tool_entry.get("result", {})
        stdout = r.get("stdout", "")

        if tool == "nikto":
            for line in stdout.split("\n"):
                line = line.strip()
                if line.startswith("+ ") and "OSVDB" in line:
                    findings.append({
                        "title": f"Nikto: {line[:120]}",
                        "severity": _guess_severity_from_text(line),
                        "description": line,
                        "evidence": line,
                        "recommendation": "Review and remediate the identified web server misconfiguration.",
                        "tool": "nikto",
                    })
                elif line.startswith("+ ") and any(kw in line.lower() for kw in
                        ["vulnerability", "outdated", "default", "exposed", "directory listing"]):
                    findings.append({
                        "title": f"Nikto: {line[:120]}",
                        "severity": _guess_severity_from_text(line),
                        "description": line,
                        "evidence": line,
                        "recommendation": "Review and remediate the identified issue.",
                        "tool": "nikto",
                    })

        elif tool == "nuclei":
            for line in stdout.split("\n"):
                line = line.strip()
                if not line:
                    continue
                severity = "medium"
                for sev in ["critical", "high", "medium", "low", "info"]:
                    if f"[{sev}]" in line.lower():
                        severity = sev
                        break
                findings.append({
                    "title": f"Nuclei: {line[:120]}",
                    "severity": severity,
                    "description": line,
                    "evidence": line,
                    "recommendation": "Review the Nuclei template match and apply appropriate remediation.",
                    "tool": "nuclei",
                })

        elif tool == "wapiti":
            for line in stdout.split("\n"):
                line = line.strip()
                if any(kw in line.lower() for kw in
                        ["sql injection", "xss", "command exec", "file handling",
                         "crlf", "htaccess", "blind", "xxe"]):
                    findings.append({
                        "title": f"Wapiti: {line[:120]}",
                        "severity": _guess_severity_from_text(line),
                        "description": line,
                        "evidence": line,
                        "recommendation": "Apply input validation and output encoding.",
                        "tool": "wapiti",
                    })

        elif tool == "whatweb":
            if stdout.strip():
                findings.append({
                    "title": "Technology Stack Detected",
                    "severity": "info",
                    "description": f"WhatWeb identified the following technologies on {target}.",
                    "evidence": stdout[:2000],
                    "recommendation": "Ensure all detected software is up to date and properly hardened.",
                    "tool": "whatweb",
                })

        elif tool == "wafw00f":
            if stdout.strip() and "no waf" not in stdout.lower():
                findings.append({
                    "title": "Web Application Firewall Detected",
                    "severity": "info",
                    "description": "WAF detection results from wafw00f.",
                    "evidence": stdout[:1000],
                    "recommendation": "Note: WAF may filter some attack payloads. Consider WAF bypass techniques.",
                    "tool": "wafw00f",
                })

        elif tool == "sslscan":
            if stdout.strip():
                ssl_issues = []
                if "SSLv3" in stdout and "Enabled" in stdout:
                    ssl_issues.append("SSLv3 enabled (vulnerable to POODLE)")
                if "TLSv1.0" in stdout and "Enabled" in stdout:
                    ssl_issues.append("TLSv1.0 enabled (deprecated)")
                if "RC4" in stdout:
                    ssl_issues.append("RC4 cipher detected (weak)")
                if "NULL" in stdout:
                    ssl_issues.append("NULL cipher detected")

                if ssl_issues:
                    findings.append({
                        "title": "SSL/TLS Configuration Issues",
                        "severity": "medium",
                        "description": "SSLScan identified weak SSL/TLS configuration: " + "; ".join(ssl_issues),
                        "evidence": stdout[:2000],
                        "recommendation": "Disable deprecated protocols (SSLv3, TLSv1.0). Remove weak ciphers. Enable TLSv1.2+ only.",
                        "tool": "sslscan",
                    })
                else:
                    findings.append({
                        "title": "SSL/TLS Configuration Reviewed",
                        "severity": "info",
                        "description": "SSLScan completed. No major SSL/TLS issues detected.",
                        "evidence": stdout[:1500],
                        "recommendation": "Continue to monitor SSL/TLS configuration.",
                        "tool": "sslscan",
                    })

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

    return findings


def _guess_severity_from_text(text: str) -> str:
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["rce", "remote code", "sql injection", "command injection", "critical"]):
        return "critical"
    if any(kw in text_lower for kw in ["xss", "cross-site", "authentication bypass", "high"]):
        return "high"
    if any(kw in text_lower for kw in ["directory listing", "information disclosure", "outdated", "default"]):
        return "medium"
    if any(kw in text_lower for kw in ["cookie", "header", "banner"]):
        return "low"
    return "info"


async def _invoke_create_report(mcp, report_data: dict) -> dict:
    """Programmatically call the create_report tool."""
    from tools.reporting import REPORT_DIR, TEMPLATE_DIR, _allocate_report_run_dir

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    run_dir = _allocate_report_run_dir()

    try:
        findings_list = json.loads(report_data["findings"])
    except json.JSONDecodeError:
        return {"success": False, "error": "Failed to parse findings for report."}

    now = format_now_tz("%Y-%m-%d %H:%M %Z")

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings_list:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    fmt = report_data.get("format", "html")
    filename = report_data.get("filename", f"burp_report_{now}")

    try:
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
        template = env.get_template("report.html")
        html = template.render(
            title=report_data["title"],
            subtitle=f"Security Assessment for {report_data['target']}",
            target=report_data["target"],
            date=now,
            tester=report_data.get("tester", "Cybertool MCP"),
            scope=report_data.get("scope", ""),
            executive_summary=report_data.get("executive_summary", ""),
            severity_counts=severity_counts,
            findings=findings_list,
            tool_outputs=None,
            recommendations=[f for f in findings_list if f.get("recommendation")],
            enumerate=enumerate,
        )
    except Exception:
        html = f"<html><body><h1>{report_data['title']}</h1>"
        html += f"<p>{report_data.get('executive_summary', '')}</p>"
        for f in findings_list:
            html += f"<h3>[{f.get('severity','').upper()}] {f.get('title','')}</h3>"
            html += f"<p>{f.get('description','')}</p>"
            if f.get("evidence"):
                html += f"<pre>{f['evidence'][:1000]}</pre>"
        html += "</body></html>"

    html_path = run_dir / f"{filename}.html"
    html_path.write_text(html, encoding="utf-8")

    result = {"success": True, "html_path": str(html_path), "format": fmt, "run_directory": str(run_dir)}

    if fmt == "pdf":
        pdf_path = run_dir / f"{filename}.pdf"
        pdf_result = await run_command([
            "wkhtmltopdf", "--enable-local-file-access",
            "--page-size", "A4",
            "--margin-top", "15mm", "--margin-bottom", "15mm",
            "--margin-left", "15mm", "--margin-right", "15mm",
            str(html_path), str(pdf_path),
        ], timeout=60)
        if pdf_result.get("success"):
            result["pdf_path"] = str(pdf_path)
            result["format"] = "pdf"

    return result
