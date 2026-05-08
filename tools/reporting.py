"""Security assessment reporting tools: generate professional pentest reports
in HTML, PDF, Markdown, JSON, and CSV formats."""

import json
import csv
import io
import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from tools.helpers import run_command, sanitize_arg, OUTPUT_DIR
from tools.contracts import ExecutiveCitation, ExecutiveSummaryReport, ExecutiveSummarySection
from tools.session_manager import get_active_session_id
from tools.time_utils import format_dt_tz, format_now_tz

REPORT_DIR = Path("/opt/uts-mcp/reports")
TEMPLATE_DIR = Path("/opt/uts-mcp/templates")
_SESSION_SLUG_RE = re.compile(r"[^A-Za-z0-9_\-]")


def _allocate_report_run_dir(session_id: str = "") -> Path:
    sid = str(session_id or get_active_session_id() or "").strip()
    sid = _SESSION_SLUG_RE.sub("_", sid)[:64] or "adhoc"
    stamp = format_now_tz("%Y%m%d_%H%M%S")
    run_dir = REPORT_DIR / sid / stamp
    if run_dir.exists():
        run_dir = REPORT_DIR / sid / f"{stamp}_{secrets.token_hex(2)}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def register_reporting_tools(mcp):

    @mcp.tool()
    async def create_report(
        title: str,
        target: str,
        findings: str,
        executive_summary: str = "",
        tester: str = "Unified ThreatLens MCP Automated Assessment",
        scope: str = "",
        format: str = "html",
        filename: str = "",
    ) -> dict:
        """Generate a professional security assessment report.

        Provide findings as a JSON array of objects, each with:
        - title (str): Finding title
        - severity (str): critical, high, medium, low, or info
        - description (str): Detailed description
        - evidence (str): Tool output or proof
        - recommendation (str): Remediation advice
        - references (str, optional): CVE IDs, URLs, etc.

        Args:
            title: Report title (e.g. "Web Application Penetration Test Report").
            target: Target system(s) tested.
            findings: JSON array of finding objects (see above).
            executive_summary: High-level summary for management.
            tester: Name of tester/team.
            scope: Scope description.
            format: Output format — html, pdf, markdown, json, csv. Default html.
            filename: Custom filename (without extension). Auto-generated if empty.
        """
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

        try:
            findings_list = json.loads(findings)
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Invalid findings JSON: {e}"}

        now = format_now_tz("%Y-%m-%d %H:%M %Z")
        date_slug = format_now_tz("%Y%m%d_%H%M%S")

        if not filename:
            safe_target = sanitize_arg(target).replace(" ", "_")[:30]
            filename = f"report_{safe_target}_{date_slug}"

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings_list.sort(key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5))

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings_list:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        fmt = format.lower().strip()

        if fmt not in {"html", "pdf", "markdown", "json", "csv"}:
            return {"success": False, "error": f"Unknown format: {fmt}. Use html, pdf, markdown, json, or csv."}

        run_dir = _allocate_report_run_dir()
        result = await _generate_html_report(
            title, target, findings_list, executive_summary,
            tester, scope, now, severity_counts, filename, run_dir
        )
        if not result.get("success"):
            return result

        bundled = await _bundle_report_artifacts(result["path"], filename)
        bundled.update(
            {
                "title": title,
                "target": target,
                "requested_format": fmt,
                "finding_count": len(findings_list),
                "run_directory": str(run_dir),
            }
        )
        return bundled

    @mcp.tool()
    async def create_report_from_tool_outputs(
        title: str,
        target: str,
        tool_results: str,
        executive_summary: str = "",
        tester: str = "Unified ThreatLens MCP Automated Assessment",
        scope: str = "",
        format: str = "html",
        filename: str = "",
    ) -> dict:
        """Generate a report directly from raw tool outputs (no manual findings needed).

        Provide tool_results as a JSON array of objects, each with:
        - tool_name (str): Name of the tool (e.g. "nmap_scan")
        - target (str): Target scanned
        - command (str): Command that was run
        - output (str): Raw tool output (stdout)
        - elapsed (float): Time taken in seconds

        Args:
            title: Report title.
            target: Target system(s).
            tool_results: JSON array of tool output objects.
            executive_summary: High-level summary.
            tester: Tester name.
            scope: Scope description.
            format: Output format — html, pdf, markdown, json. Default html.
            filename: Custom filename.
        """
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

        try:
            tool_outputs = json.loads(tool_results)
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Invalid tool_results JSON: {e}"}

        now = format_now_tz("%Y-%m-%d %H:%M %Z")
        date_slug = format_now_tz("%Y%m%d_%H%M%S")

        if not filename:
            safe_target = sanitize_arg(target).replace(" ", "_")[:30]
            filename = f"scan_report_{safe_target}_{date_slug}"

        fmt = format.lower().strip()

        if fmt not in {"html", "pdf", "markdown", "json"}:
            return {"success": False, "error": f"Unknown format: {fmt}"}

        run_dir = _allocate_report_run_dir()
        result = await _generate_tool_output_html(
            title, target, tool_outputs, executive_summary,
            tester, scope, now, filename, run_dir
        )
        if not result.get("success"):
            return result

        bundled = await _bundle_report_artifacts(result["path"], filename)
        bundled.update(
            {
                "title": title,
                "target": target,
                "requested_format": fmt,
                "tool_output_count": len(tool_outputs) if isinstance(tool_outputs, list) else 0,
                "run_directory": str(run_dir),
            }
        )
        return bundled

    @mcp.tool()
    async def list_reports() -> dict:
        """List all generated reports."""
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        reports = []
        for p in sorted(REPORT_DIR.rglob("*")):
            if p.is_file():
                reports.append({
                    "path": str(p),
                    "name": p.name,
                    "size_kb": round(p.stat().st_size / 1024, 1),
                    "modified": format_dt_tz(
                        datetime.fromtimestamp(p.stat().st_mtime),
                        "%Y-%m-%d %H:%M %Z",
                    ),
                })
        return {"success": True, "reports": reports, "count": len(reports)}

    @mcp.tool()
    async def read_report(report_path: str) -> dict:
        """Read the contents of a generated report.

        Args:
            report_path: Path to the report file.
        """
        path = Path(sanitize_arg(report_path))
        if not path.exists():
            return {"success": False, "error": f"Report not found: {path}"}
        content = path.read_text(encoding="utf-8", errors="replace")[:500_000]
        return {"success": True, "path": str(path), "content": content}

    @mcp.tool()
    async def convert_report_to_pdf(html_path: str, output_path: str = "") -> dict:
        """Convert an HTML report to PDF using wkhtmltopdf.

        Args:
            html_path: Path to the HTML report.
            output_path: Output PDF path. Auto-generated if empty.
        """
        return await _convert_html_to_pdf(html_path, output_path)

    @mcp.tool()
    async def save_report_artifact(
        content: str,
        filename: str = "",
        format: str = "html",
    ) -> dict:
        """Save ad-hoc report content into the reports directory.

        Use this when report content was produced outside create_report/create_report_from_tool_outputs
        but still needs to be persisted and visible in the dashboard.

        Args:
            content: Report body text/content.
            filename: Optional filename without extension.
            format: html, markdown, txt, json, csv.
        """
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        fmt_map = {
            "html": "html",
            "markdown": "md",
            "md": "md",
            "txt": "txt",
            "text": "txt",
            "json": "json",
            "csv": "csv",
        }
        fmt_raw = sanitize_arg(format).lower().strip()
        if fmt_raw not in fmt_map:
            return {
                "success": False,
                "error": "Unknown format. Use html, markdown, txt, json, or csv.",
            }

        ext = fmt_map[fmt_raw]
        if not filename:
            stamp = format_now_tz("%Y%m%d_%H%M%S")
            filename = f"report_artifact_{stamp}"
        safe_name = sanitize_arg(filename).replace(" ", "_").strip("_")
        if not safe_name:
            safe_name = "report_artifact"

        run_dir = _allocate_report_run_dir()
        path = run_dir / f"{safe_name}.{ext}"
        path.write_text(content, encoding="utf-8")
        return {
            "success": True,
            "path": str(path),
            "format": ext,
            "source": "save_report_artifact",
            "run_directory": str(run_dir),
        }

    @mcp.tool()
    async def generate_executive_summary_from_session(session_id: str) -> dict:
        """Generate an evidence-cited executive summary from audit + chat + report artifacts."""
        return generate_executive_summary_from_session(session_id)


def _redact_sensitive_text(value: str) -> str:
    text = str(value or "")
    patterns = [
        r"(?i)(password|passwd|token|api[_-]?key|authorization)\s*[:=]\s*['\"]?([^\s'\"]+)",
        r"AKIA[0-9A-Z]{16}",
        r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----",
    ]
    for pattern in patterns:
        text = re.sub(pattern, "[REDACTED]", text)
    return text


def _citations_from_events(events: list[dict], limit: int = 8) -> list[ExecutiveCitation]:
    rows: list[ExecutiveCitation] = []
    for event in events:
        payload = event.get("payload", {})
        payload = payload if isinstance(payload, dict) else {}
        rows.append(
            ExecutiveCitation(
                source="audit_log",
                quote=_redact_sensitive_text(json.dumps(payload, ensure_ascii=True)[:300]),
                event_type=str(event.get("event_type", "")),
                timestamp=str(event.get("timestamp", "")),
            )
        )
        if len(rows) >= limit:
            break
    return rows


def _build_exec_section(title: str, content: str, citations: list[ExecutiveCitation]) -> ExecutiveSummarySection:
    return ExecutiveSummarySection(title=title, content=_redact_sensitive_text(content), citations=citations)


def generate_executive_summary_from_session(session_id: str) -> dict:
    from tools.dashboard_server import _build_dashboard_state  # local import to avoid cycles at import time

    state = _build_dashboard_state()
    detail = state.get("session_details", {}).get(session_id)
    if not detail:
        return {"success": False, "error": f"Unknown session: {session_id}"}

    events = list(detail.get("events", []))
    turns = list(detail.get("chat_turns", []))
    reports = list(detail.get("reports", []))
    citations = _citations_from_events(events, limit=10)

    tool_set = sorted(set(str(t) for t in detail.get("tools", [])))
    failures = [e for e in events if str(e.get("event_type", "")).endswith(".error")]
    context_text = (
        f"Session {session_id} executed {len(tool_set)} tools over {len(events)} events and {len(turns)} chat turns."
    )
    findings_text = (
        f"Primary findings were derived from tool outputs and generated artifacts. "
        f"Observed tools: {', '.join(tool_set[:12]) or 'none'}."
    )
    impact_text = (
        "Security findings may affect confidentiality, integrity, and availability depending on "
        "severity and exploitability of discovered issues."
    )
    mitre_text = (
        "Mapped themes include credential abuse (T1078), persistence mechanisms (T1053/T1543), "
        "and potential defense evasion/log tampering (T1070) where evidence indicates."
    )
    recommendations_text = (
        "Prioritize remediation by risk: close internet-exposed critical paths first, rotate potentially exposed "
        "credentials/secrets, then harden monitoring and detection coverage."
    )
    limitations_text = (
        f"Summary is generated from available session evidence only. Failures observed: {len(failures)}. "
        "Conclusions should be validated with environment owners and additional telemetry."
    )

    report = ExecutiveSummaryReport(
        session_id=session_id,
        generated_at=format_now_tz("%Y-%m-%d %H:%M:%S %Z"),
        context=_build_exec_section("Context", context_text, citations[:3]),
        key_findings=_build_exec_section("Key Findings", findings_text, citations[3:6]),
        business_impact=_build_exec_section("Business Impact", impact_text, citations[6:8]),
        mitre_mapping=_build_exec_section("MITRE Mapping", mitre_text, citations[8:10]),
        recommendations=_build_exec_section("Prioritized Recommendations", recommendations_text, citations[:2]),
        confidence_and_limitations=_build_exec_section("Confidence and Limitations", limitations_text, citations[-2:]),
    )
    output = report.model_dump()
    output["artifacts"] = reports
    output["guardrails"] = {
        "redaction_applied": True,
        "citation_count": sum(len(section["citations"]) for section in output.values() if isinstance(section, dict) and "citations" in section),
        "hallucination_policy": "No unsupported claim beyond captured session evidence.",
    }
    return {"success": True, "summary": output}


async def _generate_html_report(title, target, findings, exec_summary,
                                  tester, scope, date, severity_counts, filename, target_dir: Path):
    try:
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
        template = env.get_template("report.html")
        html = template.render(
            title=title, subtitle=f"Security Assessment for {target}",
            target=target, date=date, tester=tester, scope=scope,
            executive_summary=exec_summary,
            severity_counts=severity_counts,
            findings=findings,
            tool_outputs=None,
            recommendations=[f for f in findings if f.get("recommendation")],
            enumerate=enumerate,
        )
    except ImportError:
        html = _fallback_html(title, target, findings, exec_summary, tester, scope, date, severity_counts)

    path = target_dir / f"{sanitize_arg(filename)}.html"
    path.write_text(html, encoding="utf-8")
    return {"success": True, "path": str(path), "format": "html", "finding_count": len(findings)}


async def _generate_tool_output_html(title, target, tool_outputs, exec_summary,
                                       tester, scope, date, filename, target_dir: Path):
    try:
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
        template = env.get_template("report.html")
        html = template.render(
            title=title, subtitle=f"Scan Results for {target}",
            target=target, date=date, tester=tester, scope=scope,
            executive_summary=exec_summary,
            severity_counts=None, findings=None,
            tool_outputs=tool_outputs,
            recommendations=None, enumerate=enumerate,
        )
    except ImportError:
        html = f"<html><body><h1>{title}</h1><p>{exec_summary}</p>"
        for t in tool_outputs:
            html += f"<h2>{t.get('tool_name','')}</h2><pre>{t.get('output','')}</pre>"
        html += "</body></html>"

    path = target_dir / f"{sanitize_arg(filename)}.html"
    path.write_text(html, encoding="utf-8")

    return {"success": True, "path": str(path), "format": "html"}


def _generate_markdown_report(title, target, findings, exec_summary,
                                tester, scope, date, severity_counts, filename, target_dir: Path):
    lines = [
        f"# {title}",
        "",
        f"**Target:** {target}  ",
        f"**Date:** {date}  ",
        f"**Tester:** {tester}  ",
        f"**Scope:** {scope}",
        "",
        "## Severity Summary",
        "",
        f"| Critical | High | Medium | Low | Info |",
        f"|:---:|:---:|:---:|:---:|:---:|",
        f"| {severity_counts['critical']} | {severity_counts['high']} | {severity_counts['medium']} | {severity_counts['low']} | {severity_counts['info']} |",
        "",
    ]

    if exec_summary:
        lines.extend(["## Executive Summary", "", exec_summary, ""])

    lines.extend(["## Findings", ""])

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").upper()
        lines.append(f"### {i}. [{sev}] {f.get('title', 'Untitled')}")
        lines.append("")
        if f.get("description"):
            lines.extend([f.get("description"), ""])
        if f.get("evidence"):
            lines.extend(["**Evidence:**", "```", f.get("evidence"), "```", ""])
        if f.get("recommendation"):
            lines.extend([f"> **Recommendation:** {f.get('recommendation')}", ""])
        if f.get("references"):
            lines.extend([f"**References:** {f.get('references')}", ""])
        lines.append("---")
        lines.append("")

    lines.extend([
        "",
        f"*Generated by Unified ThreatLens MCP Security Server | {date}*",
    ])

    path = target_dir / f"{sanitize_arg(filename)}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return {"success": True, "path": str(path), "format": "markdown", "finding_count": len(findings)}


def _generate_tool_output_markdown(title, target, tool_outputs, exec_summary,
                                     tester, scope, date, filename, target_dir: Path):
    lines = [
        f"# {title}",
        "",
        f"**Target:** {target}  ",
        f"**Date:** {date}  ",
        f"**Tester:** {tester}  ",
        f"**Scope:** {scope}",
        "",
    ]
    if exec_summary:
        lines.extend(["## Executive Summary", "", exec_summary, ""])

    lines.extend(["## Tool Outputs", ""])
    for t in tool_outputs:
        lines.append(f"### {t.get('tool_name', 'Unknown')}")
        if t.get("target"):
            lines.append(f"**Target:** {t['target']}")
        if t.get("command"):
            lines.append(f"**Command:** `{t['command']}`")
        if t.get("elapsed"):
            lines.append(f"**Duration:** {t['elapsed']}s")
        lines.extend(["", "```", t.get("output", ""), "```", "", "---", ""])

    path = target_dir / f"{sanitize_arg(filename)}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return {"success": True, "path": str(path), "format": "markdown"}


def _generate_json_report(title, target, findings, exec_summary,
                            tester, scope, date, severity_counts, filename, target_dir: Path):
    report = {
        "title": title,
        "target": target,
        "date": date,
        "tester": tester,
        "scope": scope,
        "executive_summary": exec_summary,
        "severity_summary": severity_counts,
        "total_findings": len(findings),
        "findings": findings,
    }
    path = target_dir / f"{sanitize_arg(filename)}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"success": True, "path": str(path), "format": "json", "finding_count": len(findings)}


def _generate_csv_report(findings, filename, target_dir: Path):
    path = target_dir / f"{sanitize_arg(filename)}.csv"
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["#", "Severity", "Title", "Description", "Evidence", "Recommendation", "References"])
    for i, f in enumerate(findings, 1):
        writer.writerow([
            i,
            f.get("severity", "info"),
            f.get("title", ""),
            f.get("description", ""),
            f.get("evidence", "")[:500],
            f.get("recommendation", ""),
            f.get("references", ""),
        ])
    path.write_text(buf.getvalue(), encoding="utf-8")
    return {"success": True, "path": str(path), "format": "csv", "finding_count": len(findings)}


async def _convert_html_to_pdf(html_path, filename):
    html_source = Path(html_path)
    if not filename:
        filename = html_source.stem
    pdf_path = html_source.parent / f"{sanitize_arg(filename)}.pdf"

    result = await run_command([
        "wkhtmltopdf",
        "--enable-local-file-access",
        "--page-size", "A4",
        "--margin-top", "15mm",
        "--margin-bottom", "15mm",
        "--margin-left", "15mm",
        "--margin-right", "15mm",
        str(html_source),
        str(pdf_path),
    ], timeout=60)

    if result.get("success"):
        return {"success": True, "path": str(pdf_path), "format": "pdf", "html_source": str(html_source)}

    return {
        "success": False,
        "error": f"PDF conversion failed: {result.get('stderr', '')}",
        "html_path": str(html_source),
    }


async def _convert_html_to_docx(html_path, filename):
    html_source = Path(html_path)
    if not filename:
        filename = html_source.stem
    docx_path = html_source.parent / f"{sanitize_arg(filename)}.docx"

    result = await run_command([
        "pandoc",
        str(html_source),
        "-o",
        str(docx_path),
    ], timeout=90)

    if result.get("success"):
        return {"success": True, "path": str(docx_path), "format": "docx", "html_source": str(html_source)}

    return {
        "success": False,
        "error": f"DOCX conversion failed: {result.get('stderr', '')}",
        "html_path": str(html_source),
    }


async def _bundle_report_artifacts(html_path: str, filename: str) -> dict:
    html_resolved = str(Path(html_path))
    base_name = sanitize_arg(filename or Path(html_resolved).stem)
    artifacts = {"html": html_resolved, "pdf": "", "docx": ""}
    errors = {}

    pdf = await _convert_html_to_pdf(html_resolved, base_name)
    if pdf.get("success"):
        artifacts["pdf"] = str(pdf.get("path", ""))
    else:
        errors["pdf"] = str(pdf.get("error", "PDF conversion failed"))

    docx = await _convert_html_to_docx(html_resolved, base_name)
    if docx.get("success"):
        artifacts["docx"] = str(docx.get("path", ""))
    else:
        errors["docx"] = str(docx.get("error", "DOCX conversion failed"))

    response = {
        "success": True,
        "format": "html",
        "path": html_resolved,
        "artifacts": artifacts,
        "report_paths": [p for p in artifacts.values() if p],
    }
    if errors:
        response["conversion_errors"] = errors
    return response


def _fallback_html(title, target, findings, exec_summary, tester, scope, date, counts):
    sev_colors = {"critical": "#dc2626", "high": "#ef4444", "medium": "#f97316", "low": "#eab308", "info": "#3b82f6"}
    html = f"""<!DOCTYPE html><html><head><meta charset='UTF-8'><title>{title}</title>
<style>body{{font-family:system-ui;max-width:900px;margin:auto;padding:2rem;background:#0f172a;color:#e2e8f0}}
h1{{color:#3b82f6}}h2{{color:#3b82f6;border-bottom:1px solid #475569;padding-bottom:.5rem}}
.finding{{background:#1e293b;padding:1rem;margin:1rem 0;border-radius:8px;border-left:4px solid #475569}}
pre{{background:#000;padding:.75rem;border-radius:6px;overflow-x:auto;font-size:.85rem}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700;color:#fff}}
</style></head><body>
<h1>{title}</h1><p>Target: {target} | Date: {date} | Tester: {tester}</p>"""
    if exec_summary:
        html += f"<h2>Executive Summary</h2><p>{exec_summary}</p>"
    html += "<h2>Findings</h2>"
    for f in findings:
        sev = f.get("severity", "info").lower()
        color = sev_colors.get(sev, "#3b82f6")
        html += f"""<div class='finding' style='border-left-color:{color}'>
<h3><span class='badge' style='background:{color}'>{sev.upper()}</span> {f.get('title','')}</h3>
<p>{f.get('description','')}</p>"""
        if f.get("evidence"):
            html += f"<pre>{f['evidence'][:2000]}</pre>"
        if f.get("recommendation"):
            html += f"<p><strong>Recommendation:</strong> {f['recommendation']}</p>"
        html += "</div>"
    html += f"<footer style='text-align:center;color:#94a3b8;margin-top:2rem'>Generated by Unified ThreatLens MCP | {date}</footer></body></html>"
    return html
