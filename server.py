"""Cybertool a Cyber Operations Linux MCP Server — exposes 279+ security tools to AI agents via Model Context Protocol."""

import argparse
import asyncio
import functools
import inspect
import os
import time
import uuid
from fastmcp import FastMCP
from tools.audit_logger import (
    audit_context,
    extract_session_id,
    write_audit_event,
)
from tools.subscription import build_subscription_blocked_response, get_subscription_status
from tools.dashboard_server import start_dashboard_server
from tools.session_manager import get_active_session_id, set_active_session_id


def _is_auto_session_id(value: str) -> bool:
    return str(value or "").strip().startswith("auto-")


def _derive_main_session_id(call_args, active_session_id: str, effective_session_id: str) -> str:
    if isinstance(call_args, dict):
        direct_main = str(call_args.get("main_session_id", "")).strip()
        if direct_main:
            return direct_main
        explicit_sid = str(call_args.get("session_id", "")).strip()
        if explicit_sid and not _is_auto_session_id(explicit_sid):
            return explicit_sid
    if active_session_id and not _is_auto_session_id(active_session_id):
        return active_session_id
    if effective_session_id and not _is_auto_session_id(effective_session_id):
        return effective_session_id
    return ""


def _install_tool_audit_hook(mcp_instance: FastMCP) -> None:
    """Wrap mcp.tool decorators to audit every tool invocation/result."""
    original_tool = mcp_instance.tool

    @functools.wraps(original_tool)
    def audited_tool(*decorator_args, **decorator_kwargs):
        base_decorator = original_tool(*decorator_args, **decorator_kwargs)

        def decorate(func):
            def _call_args(args, kwargs):
                try:
                    bound = inspect.signature(func).bind_partial(*args, **kwargs)
                    return dict(bound.arguments)
                except Exception:
                    return {"args": list(args), "kwargs": kwargs}

            def _chat_session_id_from_args(call_args: dict) -> str:
                if not isinstance(call_args, dict):
                    return ""
                direct = str(call_args.get("chat_session_id", "")).strip()
                if direct:
                    return direct
                nested = call_args.get("args")
                if isinstance(nested, dict):
                    return str(nested.get("chat_session_id", "")).strip()
                return ""

            def _identity_fields(
                *,
                session_id: str,
                main_session_id: str,
                call_args: dict,
            ) -> dict:
                fields = {
                    "session_id": session_id,
                    "mcp_session_id": session_id,
                }
                chat_session_id = _chat_session_id_from_args(call_args)
                if chat_session_id:
                    fields["chat_session_id"] = chat_session_id
                if main_session_id:
                    fields["main_session_id"] = main_session_id
                return fields

            def _blocked_result_if_inactive(
                *,
                tool_name: str,
                session_id: str,
                main_session_id: str,
                call_args: dict,
                invocation_id: str,
                start_time: float,
            ):
                subscription_status = get_subscription_status()
                if subscription_status.get("active"):
                    return None
                blocked = build_subscription_blocked_response(tool_name, subscription_status)
                blocked_payload = {
                    "tool": tool_name,
                    **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                    "invocation_id": invocation_id,
                    "elapsed_seconds": round(time.time() - start_time, 3),
                    "subscription": subscription_status,
                }
                write_audit_event("subscription.blocked_call", blocked_payload)
                result_payload = {
                    "tool": tool_name,
                    **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                    "invocation_id": invocation_id,
                    "elapsed_seconds": round(time.time() - start_time, 3),
                    "result": blocked,
                }
                write_audit_event("tool.result", result_payload)
                return blocked

            if inspect.iscoroutinefunction(func):
                @functools.wraps(func)
                async def wrapped(*args, **kwargs):
                    start = time.time()
                    invocation_id = f"inv-{uuid.uuid4().hex}"
                    call_args = _call_args(args, kwargs)
                    active_session_id = get_active_session_id()
                    session_id = extract_session_id(call_args) or active_session_id
                    if not session_id:
                        session_id = f"auto-{uuid.uuid4().hex}"
                        set_active_session_id(session_id)
                        session_start_payload = {
                            "session_id": session_id,
                            "mcp_session_id": session_id,
                            "source": "implicit_auto",
                            "tool": func.__name__,
                            "invocation_id": invocation_id,
                        }
                        write_audit_event("session.start", session_start_payload)
                    main_session_id = _derive_main_session_id(call_args, active_session_id, session_id)
                    invoke_payload = {
                        "tool": func.__name__,
                        **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                        "invocation_id": invocation_id,
                        "args": call_args,
                    }
                    write_audit_event(
                        "tool.invoke",
                        invoke_payload,
                    )
                    blocked = _blocked_result_if_inactive(
                        tool_name=func.__name__,
                        session_id=session_id,
                        main_session_id=main_session_id,
                        call_args=call_args,
                        invocation_id=invocation_id,
                        start_time=start,
                    )
                    if blocked is not None:
                        return blocked
                    try:
                        with audit_context(tool=func.__name__, session_id=session_id, invocation_id=invocation_id):
                            result = await func(*args, **kwargs)
                            result_payload = {
                                "tool": func.__name__,
                                **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                                "invocation_id": invocation_id,
                                "elapsed_seconds": round(time.time() - start, 3),
                                "result": result,
                            }
                            write_audit_event(
                                "tool.result",
                                result_payload,
                            )
                            return result
                    except asyncio.CancelledError as exc:
                        with audit_context(tool=func.__name__, session_id=session_id, invocation_id=invocation_id):
                            cancelled_payload = {
                                "tool": func.__name__,
                                **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                                "invocation_id": invocation_id,
                                "elapsed_seconds": round(time.time() - start, 3),
                                "error": str(exc),
                                "error_type": type(exc).__name__,
                            }
                            write_audit_event("tool.cancelled", cancelled_payload)
                        raise
                    except Exception as exc:
                        with audit_context(tool=func.__name__, session_id=session_id, invocation_id=invocation_id):
                            error_payload = {
                                "tool": func.__name__,
                                **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                                "invocation_id": invocation_id,
                                "elapsed_seconds": round(time.time() - start, 3),
                                "error": str(exc),
                                "error_type": type(exc).__name__,
                            }
                            write_audit_event(
                                "tool.error",
                                error_payload,
                            )
                            raise
                    except BaseException as exc:
                        with audit_context(tool=func.__name__, session_id=session_id, invocation_id=invocation_id):
                            error_payload = {
                                "tool": func.__name__,
                                **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                                "invocation_id": invocation_id,
                                "elapsed_seconds": round(time.time() - start, 3),
                                "error": str(exc),
                                "error_type": type(exc).__name__,
                                "base_exception": True,
                            }
                            write_audit_event("tool.error", error_payload)
                        raise
            else:
                @functools.wraps(func)
                def wrapped(*args, **kwargs):
                    start = time.time()
                    invocation_id = f"inv-{uuid.uuid4().hex}"
                    call_args = _call_args(args, kwargs)
                    active_session_id = get_active_session_id()
                    session_id = extract_session_id(call_args) or active_session_id
                    if not session_id:
                        session_id = f"auto-{uuid.uuid4().hex}"
                        set_active_session_id(session_id)
                        session_start_payload = {
                            "session_id": session_id,
                            "mcp_session_id": session_id,
                            "source": "implicit_auto",
                            "tool": func.__name__,
                            "invocation_id": invocation_id,
                        }
                        write_audit_event("session.start", session_start_payload)
                    main_session_id = _derive_main_session_id(call_args, active_session_id, session_id)
                    invoke_payload = {
                        "tool": func.__name__,
                        **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                        "invocation_id": invocation_id,
                        "args": call_args,
                    }
                    write_audit_event(
                        "tool.invoke",
                        invoke_payload,
                    )
                    blocked = _blocked_result_if_inactive(
                        tool_name=func.__name__,
                        session_id=session_id,
                        main_session_id=main_session_id,
                        call_args=call_args,
                        invocation_id=invocation_id,
                        start_time=start,
                    )
                    if blocked is not None:
                        return blocked
                    try:
                        with audit_context(tool=func.__name__, session_id=session_id, invocation_id=invocation_id):
                            result = func(*args, **kwargs)
                            result_payload = {
                                "tool": func.__name__,
                                **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                                "invocation_id": invocation_id,
                                "elapsed_seconds": round(time.time() - start, 3),
                                "result": result,
                            }
                            write_audit_event(
                                "tool.result",
                                result_payload,
                            )
                            return result
                    except Exception as exc:
                        with audit_context(tool=func.__name__, session_id=session_id, invocation_id=invocation_id):
                            error_payload = {
                                "tool": func.__name__,
                                **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                                "invocation_id": invocation_id,
                                "elapsed_seconds": round(time.time() - start, 3),
                                "error": str(exc),
                                "error_type": type(exc).__name__,
                            }
                            write_audit_event(
                                "tool.error",
                                error_payload,
                            )
                            raise
                    except BaseException as exc:
                        with audit_context(tool=func.__name__, session_id=session_id, invocation_id=invocation_id):
                            error_payload = {
                                "tool": func.__name__,
                                **_identity_fields(session_id=session_id, main_session_id=main_session_id, call_args=call_args),
                                "invocation_id": invocation_id,
                                "elapsed_seconds": round(time.time() - start, 3),
                                "error": str(exc),
                                "error_type": type(exc).__name__,
                                "base_exception": True,
                            }
                            write_audit_event("tool.error", error_payload)
                        raise

            return base_decorator(wrapped)

        return decorate

    mcp_instance.tool = audited_tool

mcp = FastMCP(
    "cybertool-mcp",
    instructions=(
        "You are connected to Cybertool a Cyber Operations Linux security toolkit via MCP. "
        "You have access to 279+ penetration testing and security tools spanning 21 categories: "
        "Network Recon (Nmap, Masscan, ZMap, hping3), "
        "Web Security (Nikto, SQLMap, Gobuster, ffuf, Feroxbuster, Nuclei, OWASP ZAP, Commix, XSSer, Wapiti, Skipfish — all HTTPS-aware), "
        "Burp Suite Pipeline (burp_scan_with_report for full automated crawl+audit+report, burp_check_vulns for targeted SQLi/XSS/RCE/SSRF checks, burp_sitemap_crawl for endpoint discovery), "
        "SSL/TLS Testing (sslscan, sslyze, testssl.sh, openssl, Heartbleed/POODLE/ROBOT checks, cert inspection, cipher enum, HSTS/security headers), "
        "Post-Quantum Cryptography (pqc_full_assessment for scored readiness reports, pqc_kex_probe for Kyber/ML-KEM group testing, pqc_cert_check for quantum-vulnerability analysis, pqc_quantum_risk_summary for quick risk rating, testssl_pqc and sslyze_pqc for PQC-filtered scans), "
        "Disk Incident Response (ssh_keygen_for_remote_setup + remote_ssh_preflight onboarding, remote_linux_disk_triage/remediate/cleanup over SSH, remote forensic disk imaging, attached read-only disk root-cause analysis, attached_disk_compromise_investigation for offline compromise forensics), "
        "Brute-Force (Hydra, John, Hashcat, Patator, Crowbar, BruteSpray), "
        "OSINT (theHarvester, Amass, Subfinder, Sherlock, SpiderFoot, Shodan), "
        "Exploitation & Post-Exploitation (Metasploit, SearchSploit, SET, GoPhish, Weevely, RouterSploit, Chisel, sshuttle), "
        "Active Directory (CrackMapExec, NetExec, Impacket, BloodHound, Kerbrute, Responder, Evil-WinRM, smbmap, rpcclient, Certipy), "
        "Wireless & WiFi Cracking (Aircrack-ng, Wifite, Reaver, Bully, Pyrit, Hashcat WPA, hcxtools, Wifiphisher, mdk4, asleap — full crack pipeline), "
        "Sniffing/Spoofing (Bettercap, Ettercap, dsniff, mitm6, sslstrip, dnschef, mitmproxy), "
        "Stress Testing (SlowHTTPTest, Siege, GoldenEye, t50), "
        "Forensics (Binwalk, Sleuth Kit, Volatility3, YARA, bulk_extractor), "
        "Reverse Engineering (Radare2, Rizin, Ghidra, GDB, strace, apktool, JADX), "
        "Steganography (Steghide, OutGuess, StegCracker), "
        "Vulnerability Scanning (WPScan, Lynis, chkrootkit, ClamAV), "
        "Database (ODAT, sqlninja, oscanner), "
        "VoIP (SIPVicious, SIPp, enumIAX), "
        "Crypto/Encoding utilities, "
        "and Professional Reporting (HTML, PDF, Markdown, JSON, CSV with severity dashboards). "
        "All tool databases can be updated via update_all_databases or update_tool_database. "
        "All web tools support HTTPS targets natively. "
        "Use these tools responsibly and only against authorized targets. "
        "Always validate that the user has explicit permission to test any target. "
        "After completing any assessment, offer to generate a professional report using create_report. "
        "When the user asks to generate a report, do not output standalone HTML in chat. "
        "You must call create_report or create_report_from_tool_outputs so the report is saved under /opt/uts-mcp/reports, "
        "or call save_report_artifact for ad-hoc content, then return the saved report path. "
        "At the start of each new user request/turn, you MUST call start_session (prefer passing chat_session_id) "
        "so all tool and command events are grouped under a single session_id in the audit log and dashboard. "
        "To preserve full chat history in the dashboard, call save_chat_exchange after each completed turn "
        "using a stable chat_session_id and include any report paths generated in that turn."
    ),
)

_install_tool_audit_hook(mcp)
write_audit_event("server.start", {"service": "cybertool-mcp"})
if os.environ.get("MCP_DASHBOARD_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}:
    start_dashboard_server(mcp)
    write_audit_event("dashboard.start", {"service": "cybertool-mcp-dashboard"})

from tools import register_all_tools  # noqa: E402

register_all_tools(mcp)


def main():
    parser = argparse.ArgumentParser(description="Cybertool MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    elif args.transport == "streamable-http":
        mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
