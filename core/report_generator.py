"""
DORAKULA Report Generator Module
==================================
Professional report generation for bug bounty engagement findings.
Supports HTML, Markdown, and JSON output formats with severity
color-coding, CVSS references, and remediation priority matrices.

Author: DORAKULA Framework
License: Offensive Security Use Only
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.database import DorakulaDatabase

logger = logging.getLogger("dorakula.core.report_generator")

REPORTS_DIR = "./reports"


class ReportGenerator:
    """Professional report generator for DORAKULA engagement findings.

    Generates HTML, Markdown, and JSON reports with severity badges,
    CVSS calculator references, and remediation priority matrices.
    Supports AI-generated executive summaries via the ai_router.

    Attributes:
        reports_dir: Directory where generated reports are saved.
    """

    SEVERITY_COLORS: Dict[str, str] = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#28a745",
        "info": "#17a2b8",
    }

    SEVERITY_BG: Dict[str, str] = {
        "critical": "#f8d7da",
        "high": "#fff3cd",
        "medium": "#fff9e6",
        "low": "#d4edda",
        "info": "#d1ecf1",
    }

    SEVERITY_PRIORITY: Dict[str, int] = {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4,
        "info": 5,
    }

    def __init__(self, reports_dir: str = REPORTS_DIR) -> None:
        """Initialize the report generator.

        Args:
            reports_dir: Directory path for saving generated reports.
                        Defaults to ./reports/
        """
        self.reports_dir: str = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)
        logger.info("ReportGenerator initialized, output dir: %s", self.reports_dir)

    def _render_severity_badge(self, severity: str) -> str:
        """Render a color-coded severity badge as HTML.

        Args:
            severity: Severity level (critical, high, medium, low, info).

        Returns:
            HTML string for the severity badge.
        """
        color = self.SEVERITY_COLORS.get(severity.lower(), "#6c757d")
        return (
            f'<span style="background-color:{color};color:#fff;'
            f'padding:4px 12px;border-radius:4px;font-size:12px;'
            f'font-weight:bold;text-transform:uppercase;">'
            f"{severity.upper()}</span>"
        )

    def _render_finding_html(self, finding: Dict) -> str:
        """Render a single finding as an HTML card.

        Args:
            finding: Dictionary containing finding data.

        Returns:
            HTML string for the finding card.
        """
        severity = finding.get("severity", "info").lower()
        bg_color = self.SEVERITY_BG.get(severity, "#f8f9fa")
        border_color = self.SEVERITY_COLORS.get(severity, "#6c757d")
        badge = self._render_severity_badge(severity)

        cvss_score = finding.get("cvss_score", "N/A")
        cvss_vector = finding.get("cvss_vector", "")

        html = f"""
        <div style="border-left:4px solid {border_color};background-color:{bg_color};
                    padding:16px;margin:12px 0;border-radius:4px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h3 style="margin:0;color:#333;">{finding.get('title', 'Untitled Finding')}</h3>
                {badge}
            </div>
            <table style="width:100%;margin-top:12px;border-collapse:collapse;">
                <tr>
                    <td style="padding:4px 8px;font-weight:bold;width:120px;">CVSS Score:</td>
                    <td style="padding:4px 8px;">{cvss_score}"""
        if cvss_vector:
            html += f' <a href="https://www.first.org/cvss/calculator#{cvss_vector}" target="_blank" style="color:#0066cc;">[Calculator]</a>'
        html += f"""</td>
                </tr>
                <tr>
                    <td style="padding:4px 8px;font-weight:bold;">URL:</td>
                    <td style="padding:4px 8px;"><code>{finding.get('url', 'N/A')}</code></td>
                </tr>
                <tr>
                    <td style="padding:4px 8px;font-weight:bold;">Parameter:</td>
                    <td style="padding:4px 8px;"><code>{finding.get('parameter', 'N/A')}</code></td>
                </tr>
                <tr>
                    <td style="padding:4px 8px;font-weight:bold;">Tool:</td>
                    <td style="padding:4px 8px;">{finding.get('tool', 'Manual')}</td>
                </tr>
            </table>
            <div style="margin-top:12px;">
                <strong>Description:</strong>
                <p style="margin:4px 0;">{finding.get('description', 'No description provided.')}</p>
            </div>
            <div style="margin-top:8px;">
                <strong>Impact:</strong>
                <p style="margin:4px 0;">{finding.get('impact', 'No impact assessment provided.')}</p>
            </div>
            <div style="margin-top:8px;">
                <strong>Remediation:</strong>
                <p style="margin:4px 0;">{finding.get('remediation', 'No remediation provided.')}</p>
            </div>"""

        if finding.get("evidence"):
            html += f"""
            <div style="margin-top:8px;">
                <strong>Evidence:</strong>
                <pre style="background:#2d2d2d;color:#f8f8f2;padding:12px;
                            border-radius:4px;overflow-x:auto;font-size:13px;">{finding.get('evidence', '')}</pre>
            </div>"""

        verified = "Yes" if finding.get("verified") else "No"
        false_pos = "Yes" if finding.get("false_positive") else "No"
        html += f"""
            <div style="margin-top:8px;font-size:12px;color:#666;">
                Verified: {verified} | False Positive: {false_pos} |
                Discovered: {finding.get('created_at', 'N/A')}
            </div>
        </div>"""
        return html

    def _build_report_structure(self, engagement: Dict, findings: List[Dict]) -> Dict:
        """Build a structured report data object from engagement and findings.

        Args:
            engagement: Dictionary with engagement metadata.
            findings: List of finding dictionaries.

        Returns:
            Structured dictionary with sections for the report.
        """
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        sorted_findings = sorted(
            findings,
            key=lambda x: self.SEVERITY_PRIORITY.get(x.get("severity", "info").lower(), 5),
        )

        critical_high = [f for f in sorted_findings if f.get("severity", "").lower() in ("critical", "high")]
        medium_low = [f for f in sorted_findings if f.get("severity", "").lower() in ("medium", "low")]
        info_only = [f for f in sorted_findings if f.get("severity", "").lower() == "info"]

        return {
            "engagement": engagement,
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_findings": len(findings),
                "severity_counts": severity_counts,
            },
            "sections": {
                "critical_high": critical_high,
                "medium_low": medium_low,
                "informational": info_only,
            },
        }

    def generate_html(self, engagement_id: str, db: DorakulaDatabase) -> str:
        """Generate a professional HTML report for an engagement.

        Args:
            engagement_id: The engagement ID to generate a report for.
            db: DorakulaDatabase instance for data retrieval.

        Returns:
            Absolute path to the generated HTML file.

        Raises:
            ValueError: If the engagement is not found.
        """
        engagement = db.get_engagement(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement not found: {engagement_id}")

        findings = db.get_findings(engagement_id)
        structure = self._build_report_structure(engagement, findings)

        severity_counts = structure["meta"]["severity_counts"]
        total = structure["meta"]["total_findings"]

        # Severity summary bar
        summary_bars = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            pct = (count / total * 100) if total > 0 else 0
            color = self.SEVERITY_COLORS.get(sev, "#6c757d")
            summary_bars += f"""
            <div style="display:flex;align-items:center;margin:4px 0;">
                <span style="width:80px;font-weight:bold;text-transform:capitalize;">{sev}</span>
                <div style="flex:1;background:#e9ecef;height:24px;border-radius:4px;overflow:hidden;">
                    <div style="width:{pct}%;background:{color};height:100%;border-radius:4px;"></div>
                </div>
                <span style="width:40px;text-align:right;">{count}</span>
            </div>"""

        # Remediation priority matrix
        priority_matrix = """
        <table style="width:100%;border-collapse:collapse;margin-top:16px;">
            <thead>
                <tr style="background:#343a40;color:#fff;">
                    <th style="padding:8px;text-align:left;">Priority</th>
                    <th style="padding:8px;text-align:left;">Severity</th>
                    <th style="padding:8px;text-align:left;">Recommended Timeline</th>
                    <th style="padding:8px;text-align:left;">Count</th>
                </tr>
            </thead>
            <tbody>
                <tr style="background:#f8d7da;">
                    <td style="padding:8px;">P1 - Immediate</td>
                    <td style="padding:8px;">Critical</td>
                    <td style="padding:8px;">24-48 hours</td>
                    <td style="padding:8px;">{0}</td>
                </tr>
                <tr style="background:#fff3cd;">
                    <td style="padding:8px;">P2 - Urgent</td>
                    <td style="padding:8px;">High</td>
                    <td style="padding:8px;">1-2 weeks</td>
                    <td style="padding:8px;">{1}</td>
                </tr>
                <tr style="background:#fff9e6;">
                    <td style="padding:8px;">P3 - Scheduled</td>
                    <td style="padding:8px;">Medium</td>
                    <td style="padding:8px;">1-3 months</td>
                    <td style="padding:8px;">{2}</td>
                </tr>
                <tr style="background:#d4edda;">
                    <td style="padding:8px;">P4 - Low Priority</td>
                    <td style="padding:8px;">Low</td>
                    <td style="padding:8px;">3-6 months</td>
                    <td style="padding:8px;">{3}</td>
                </tr>
                <tr style="background:#d1ecf1;">
                    <td style="padding:8px;">P5 - Informational</td>
                    <td style="padding:8px;">Info</td>
                    <td style="padding:8px;">Best effort</td>
                    <td style="padding:8px;">{4}</td>
                </tr>
            </tbody>
        </table>""".format(
            severity_counts.get("critical", 0),
            severity_counts.get("high", 0),
            severity_counts.get("medium", 0),
            severity_counts.get("low", 0),
            severity_counts.get("info", 0),
        )

        # Findings HTML
        findings_html = ""
        for finding in structure["sections"]["critical_high"]:
            findings_html += self._render_finding_html(finding)
        for finding in structure["sections"]["medium_low"]:
            findings_html += self._render_finding_html(finding)
        for finding in structure["sections"]["informational"]:
            findings_html += self._render_finding_html(finding)

        # Full HTML report
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DORAKULA - Security Assessment Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 3px solid #dc3545; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; color: #dc3545; font-size: 28px; }}
        .header .subtitle {{ color: #666; font-size: 14px; margin-top: 4px; }}
        h2 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 8px; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
        .confidential {{ background: #dc3545; color: #fff; padding: 4px 12px; border-radius: 4px; font-size: 11px; text-transform: uppercase; font-weight: bold; }}
        @media print {{ body {{ background: #fff; }} .container {{ box-shadow: none; padding: 0; }} }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
                <h1>DORAKULA Security Assessment</h1>
                <div class="subtitle">Vulnerability Report - {engagement.get('name', 'Unknown Engagement')}</div>
            </div>
            <span class="confidential">Confidential</span>
        </div>
        <table style="margin-top:16px;">
            <tr><td style="font-weight:bold;padding-right:16px;">Target:</td><td>{engagement.get('target', 'N/A')}</td></tr>
            <tr><td style="font-weight:bold;padding-right:16px;">Date:</td><td>{structure['meta']['generated_at']}</td></tr>
            <tr><td style="font-weight:bold;padding-right:16px;">Status:</td><td>{engagement.get('status', 'N/A').upper()}</td></tr>
        </table>
    </div>

    <h2>Executive Summary</h2>
    <p>A security assessment was conducted against <strong>{engagement.get('target', 'N/A')}</strong>.
    A total of <strong>{total}</strong> findings were identified, including
    <strong style="color:{self.SEVERITY_COLORS['critical']}">{severity_counts.get('critical', 0)} Critical</strong>,
    <strong style="color:{self.SEVERITY_COLORS['high']}">{severity_counts.get('high', 0)} High</strong>,
    <strong style="color:{self.SEVERITY_COLORS['medium']}">{severity_counts.get('medium', 0)} Medium</strong>,
    <strong style="color:{self.SEVERITY_COLORS['low']}">{severity_counts.get('low', 0)} Low</strong>, and
    <strong style="color:{self.SEVERITY_COLORS['info']}">{severity_counts.get('info', 0)} Informational</strong> issues.
    </p>

    <h2>Severity Distribution</h2>
    {summary_bars}

    <h2>Remediation Priority Matrix</h2>
    {priority_matrix}

    <h2>CVSS Reference</h2>
    <p>CVSS scores are calculated using the Common Vulnerability Scoring System v3.1.
    For detailed score breakdowns, refer to the
    <a href="https://www.first.org/cvss/v3.1/specification-document" target="_blank">CVSS v3.1 Specification</a>
    or use the <a href="https://www.first.org/cvss/calculator" target="_blank">CVSS Calculator</a>.</p>

    <h2>Detailed Findings</h2>
    {findings_html}

    <div style="margin-top:40px;padding-top:20px;border-top:2px solid #eee;color:#666;font-size:12px;">
        <p>Generated by DORAKULA Offensive Security Framework | {structure['meta']['generated_at']}</p>
        <p>This report is confidential and intended solely for the authorized recipient.</p>
    </div>
</div>
</body>
</html>"""

        # Save to file
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{engagement_id}_{timestamp}.html"
        filepath = os.path.join(self.reports_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info("Generated HTML report: %s", filepath)
        return filepath

    def generate_markdown(self, engagement_id: str, db: DorakulaDatabase) -> str:
        """Generate a Markdown report for an engagement.

        Args:
            engagement_id: The engagement ID to generate a report for.
            db: DorakulaDatabase instance for data retrieval.

        Returns:
            Absolute path to the generated Markdown file.

        Raises:
            ValueError: If the engagement is not found.
        """
        engagement = db.get_engagement(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement not found: {engagement_id}")

        findings = db.get_findings(engagement_id)
        structure = self._build_report_structure(engagement, findings)
        severity_counts = structure["meta"]["severity_counts"]
        total = structure["meta"]["total_findings"]

        lines = [
            f"# DORAKULA Security Assessment Report",
            f"",
            f"**Target:** {engagement.get('target', 'N/A')}",
            f"**Engagement:** {engagement.get('name', 'Unknown')}",
            f"**Date:** {structure['meta']['generated_at']}",
            f"**Status:** {engagement.get('status', 'N/A').upper()}",
            f"",
            f"## Executive Summary",
            f"",
            f"A security assessment identified **{total}** findings:",
            f"- Critical: {severity_counts.get('critical', 0)}",
            f"- High: {severity_counts.get('high', 0)}",
            f"- Medium: {severity_counts.get('medium', 0)}",
            f"- Low: {severity_counts.get('low', 0)}",
            f"- Info: {severity_counts.get('info', 0)}",
            f"",
            f"## Remediation Priority Matrix",
            f"",
            f"| Priority | Severity | Timeline | Count |",
            f"|----------|----------|----------|-------|",
            f"| P1 - Immediate | Critical | 24-48h | {severity_counts.get('critical', 0)} |",
            f"| P2 - Urgent | High | 1-2 weeks | {severity_counts.get('high', 0)} |",
            f"| P3 - Scheduled | Medium | 1-3 months | {severity_counts.get('medium', 0)} |",
            f"| P4 - Low | Low | 3-6 months | {severity_counts.get('low', 0)} |",
            f"| P5 - Info | Info | Best effort | {severity_counts.get('info', 0)} |",
            f"",
        ]

        for section_name, section_findings in structure["sections"].items():
            if not section_findings:
                continue
            display_name = section_name.replace("_", " ").title()
            lines.append(f"## {display_name} Findings")
            lines.append("")
            for finding in section_findings:
                lines.append(f"### {finding.get('title', 'Untitled')}")
                lines.append(f"- **Severity:** {finding.get('severity', 'N/A').upper()}")
                lines.append(f"- **CVSS:** {finding.get('cvss_score', 'N/A')}")
                lines.append(f"- **URL:** `{finding.get('url', 'N/A')}`")
                lines.append(f"- **Parameter:** `{finding.get('parameter', 'N/A')}`")
                lines.append(f"- **Description:** {finding.get('description', 'N/A')}")
                lines.append(f"- **Impact:** {finding.get('impact', 'N/A')}")
                lines.append(f"- **Remediation:** {finding.get('remediation', 'N/A')}")
                lines.append("")

        lines.append(f"---")
        lines.append(f"*Generated by DORAKULA Framework | {structure['meta']['generated_at']}*")

        content = "\n".join(lines)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{engagement_id}_{timestamp}.md"
        filepath = os.path.join(self.reports_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info("Generated Markdown report: %s", filepath)
        return filepath

    def generate_json(self, engagement_id: str, db: DorakulaDatabase) -> str:
        """Generate a JSON report for an engagement.

        Args:
            engagement_id: The engagement ID to generate a report for.
            db: DorakulaDatabase instance for data retrieval.

        Returns:
            Absolute path to the generated JSON file.

        Raises:
            ValueError: If the engagement is not found.
        """
        engagement = db.get_engagement(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement not found: {engagement_id}")

        findings = db.get_findings(engagement_id)
        structure = self._build_report_structure(engagement, findings)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{engagement_id}_{timestamp}.json"
        filepath = os.path.join(self.reports_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(structure, f, indent=2, default=str)

        logger.info("Generated JSON report: %s", filepath)
        return filepath

    async def generate_executive_summary(
        self, engagement_id: str, db: DorakulaDatabase, ai_router: Any
    ) -> str:
        """Generate an AI-powered executive summary for an engagement.

        Uses the AI router to analyze findings and produce a human-readable
        executive summary with risk assessment and prioritized recommendations.

        Args:
            engagement_id: The engagement ID to summarize.
            db: DorakulaDatabase instance for data retrieval.
            ai_router: AI router instance with an async chat method.

        Returns:
            AI-generated executive summary string.

        Raises:
            ValueError: If the engagement is not found.
            RuntimeError: If AI generation fails.
        """
        engagement = db.get_engagement(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement not found: {engagement_id}")

        findings = db.get_findings(engagement_id)
        structure = self._build_report_structure(engagement, findings)

        # Build a concise prompt for the AI
        severity_counts = structure["meta"]["severity_counts"]
        findings_summary = []
        for f in findings[:20]:  # Limit to top 20 findings to keep prompt manageable
            findings_summary.append(
                f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')} "
                f"at {f.get('url', 'N/A')} (param: {f.get('parameter', 'N/A')}, "
                f"CVSS: {f.get('cvss_score', 'N/A')})"
            )

        prompt = (
            f"You are a senior security consultant writing an executive summary for a bug bounty report.\n"
            f"Target: {engagement.get('target', 'N/A')}\n"
            f"Engagement: {engagement.get('name', 'Unknown')}\n"
            f"Total Findings: {len(findings)}\n"
            f"Severity Breakdown: Critical={severity_counts.get('critical', 0)}, "
            f"High={severity_counts.get('high', 0)}, Medium={severity_counts.get('medium', 0)}, "
            f"Low={severity_counts.get('low', 0)}, Info={severity_counts.get('info', 0)}\n\n"
            f"Top Findings:\n" + "\n".join(findings_summary) + "\n\n"
            f"Write a professional executive summary covering:\n"
            f"1. Overall risk assessment\n"
            f"2. Key vulnerabilities and their business impact\n"
            f"3. Prioritized remediation recommendations\n"
            f"4. Strategic security recommendations\n"
            f"Keep it concise and suitable for executive leadership."
        )

        try:
            summary = await ai_router.chat(prompt)
            logger.info("Generated AI executive summary for engagement %s", engagement_id)
            return summary
        except Exception as exc:
            logger.error("Failed to generate AI executive summary: %s", exc)
            raise RuntimeError(f"AI executive summary generation failed: {exc}") from exc
