#!/usr/bin/env python3
"""DORAKULA Auto-Reporting & Validation Agent (v2 — 2025 upgrade).

Upgrades over v1:
  - SARIF 2.1.0 output (industry standard for SAST/DAST tools, 2025).
  - CVSS v4.0 scoring (latest CVSS standard).
  - Executive summary auto-draft via AI (when available).
  - Severity calibration expanded (CVSS v4 + EPSS + exploitability).
  - Multi-format output: MD, JSON, HTML, SARIF, CSV.
  - PoC validation framework with safe-by-default probes.
"""
import logging, json, time, os, csv, io
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class AutoReporter:
    """Generate professional security reports from scan results (v2)."""

    SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    # CVSS v4.0 base score mapping (simplified — full v4 has Attack Vector/Complexity/etc.)
    CVSS_V4_MAP = {
        "CRITICAL": {"score": 9.5, "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"},
        "HIGH": {"score": 7.5, "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L"},
        "MEDIUM": {"score": 5.0, "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L"},
        "LOW": {"score": 2.5, "vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:L/VI:N/VA:N"},
        "INFO": {"score": 0.0, "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N"},
    }

    CVSS_V3_MAP = {
        "CRITICAL": {"score": 9.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "HIGH": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "MEDIUM": {"score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"},
        "LOW": {"score": 2.5, "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"},
        "INFO": {"score": 0.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
    }

    def __init__(self, ai_router=None):
        self._reports_dir = "/tmp/dorakula_reports"
        os.makedirs(self._reports_dir, exist_ok=True)
        self.ai_router = ai_router

    def calibrate_severity(self, finding: Dict) -> str:
        """Auto-calibrate severity based on finding context (v2 — EPSS-aware)."""
        base_severity = finding.get("severity", "INFO").upper()
        # Upgrade if exploitable
        if finding.get("exploitable") or finding.get("vulnerable"):
            if base_severity == "MEDIUM":
                return "HIGH"
            if base_severity == "LOW":
                return "MEDIUM"
        # Downgrade if only informational
        if not finding.get("evidence") and not finding.get("response_snippet"):
            if base_severity in ("HIGH", "CRITICAL"):
                return "MEDIUM"
        # EPSS-like: if exploit is publicly available, upgrade
        if finding.get("exploit_available") or finding.get("cve_id"):
            if base_severity == "HIGH":
                return "CRITICAL"
        return base_severity

    def _flatten_findings(self, scan_results: Dict) -> List[Dict]:
        """Flatten nested scan results into a list of findings."""
        all_findings = []
        for category, results in scan_results.items():
            if isinstance(results, dict):
                for key, value in results.items():
                    if isinstance(value, dict) and "findings" in value:
                        for f in value["findings"]:
                            f["category"] = category
                            f["check"] = key
                            f["calibrated_severity"] = self.calibrate_severity(f)
                            all_findings.append(f)
                    elif isinstance(value, list):
                        for f in value:
                            if isinstance(f, dict):
                                f["category"] = category
                                f["calibrated_severity"] = self.calibrate_severity(f)
                                all_findings.append(f)
        all_findings.sort(key=lambda x: self.SEVERITY_ORDER.get(x.get("calibrated_severity", "INFO"), 0), reverse=True)
        return all_findings

    def generate_markdown_report(self, scan_results: Dict, target: str = "") -> str:
        """Generate a Markdown-format security report (v2)."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        all_findings = self._flatten_findings(scan_results)

        # Executive summary (AI-drafted if available)
        exec_summary = self._draft_executive_summary(target, all_findings)

        report = f"""# DORAKULA Security Report

**Target:** {target}
**Date:** {timestamp}
**Total Findings:** {len(all_findings)}
**Report Version:** v2-2025

## Executive Summary

{exec_summary}

| Severity | Count | CVSS v4.0 Range |
|----------|-------|------------------|
| CRITICAL | {sum(1 for f in all_findings if f.get("calibrated_severity") == "CRITICAL")} | 9.0-10.0 |
| HIGH     | {sum(1 for f in all_findings if f.get("calibrated_severity") == "HIGH")} | 7.0-8.9 |
| MEDIUM   | {sum(1 for f in all_findings if f.get("calibrated_severity") == "MEDIUM")} | 4.0-6.9 |
| LOW      | {sum(1 for f in all_findings if f.get("calibrated_severity") == "LOW")} | 0.1-3.9 |
| INFO     | {sum(1 for f in all_findings if f.get("calibrated_severity") == "INFO")} | 0.0 |

## Detailed Findings

"""
        for i, finding in enumerate(all_findings, 1):
            severity = finding.get("calibrated_severity", "INFO")
            cvss_v4 = self.CVSS_V4_MAP.get(severity, {})
            cvss_v3 = self.CVSS_V3_MAP.get(severity, {})
            report += f"""### Finding #{i}: {finding.get("check", finding.get("category", "Unknown"))}

- **Severity:** {severity}
- **CVSS v4.0:** {cvss_v4.get("score", 0.0)} ({cvss_v4.get("vector", "N/A")})
- **CVSS v3.1:** {cvss_v3.get("score", 0.0)} ({cvss_v3.get("vector", "N/A")})
- **Category:** {finding.get("category", "N/A")}
- **Description:** {finding.get("reason", finding.get("note", finding.get("error", "N/A")))}

"""
            if finding.get("evidence"):
                report += f"- **Evidence:** `{finding["evidence"][:200]}`\n"
            if finding.get("response_snippet"):
                report += f"- **Response:** `{finding["response_snippet"][:200]}`\n"
            if finding.get("payload"):
                report += f"- **Payload:** `{str(finding["payload"])[:100]}`\n"
            report += "\n"

        report += """## Remediation Recommendations

1. **CRITICAL findings:** Fix immediately — these are actively exploitable. Engage incident response.
2. **HIGH findings:** Fix within 7 days. Patch or apply virtual patches.
3. **MEDIUM findings:** Plan remediation within 30 days.
4. **LOW/INFO findings:** Address in regular maintenance cycles.

## Validation Notes

All findings were detected by automated scanning. Manual verification is recommended,
especially for CRITICAL findings where false positives have highest impact.

---
*Report generated by DORAKULA v3.1.0 Auto-Reporter v2-2025*
*SARIF 2.1.0 + CVSS v4.0 + AI executive summary*
"""
        return report

    def _draft_executive_summary(self, target: str, findings: List[Dict]) -> str:
        """Draft an executive summary (AI if available, template otherwise)."""
        crit = sum(1 for f in findings if f.get("calibrated_severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("calibrated_severity") == "HIGH")
        med = sum(1 for f in findings if f.get("calibrated_severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("calibrated_severity") == "LOW")

        # Try AI summary
        if self.ai_router and self.ai_router.ollama_available:
            try:
                prompt = (
                    f"Draft a 2-paragraph executive summary for a security report. "
                    f"Target: {target}. Findings: {crit} CRITICAL, {high} HIGH, {med} MEDIUM, {low} LOW. "
                    f"Be concise, business-focused, no technical jargon."
                )
                summary = self.ai_router.query(prompt, task="quick", max_tokens=200)
                if summary and len(summary) > 50:
                    return summary
            except Exception:
                pass

        # Template fallback
        return (
            f"A security assessment of {target or 'the target'} identified {len(findings)} findings: "
            f"{crit} CRITICAL, {high} HIGH, {med} MEDIUM, and {low} LOW severity issues. "
            f"{'Immediate action is required to address critical vulnerabilities that pose imminent risk.' if crit else ''} "
            f"{'High-severity findings should be remediated within 7 days.' if high else ''} "
            f"The detailed findings section provides specific evidence and CVSS v4.0 scores for each issue."
        )

    def generate_json_report(self, scan_results: Dict, target: str = "") -> Dict:
        """Generate a JSON-format security report (v2 — with CVSS v4)."""
        return {
            "target": target,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "generator": "DORAKULA v3.1.0 Auto-Reporter v2-2025",
            "cvss_version": "4.0",
            "scan_results": scan_results,
            "findings_flat": self._flatten_findings(scan_results),
        }

    def generate_sarif_report(self, scan_results: Dict, target: str = "") -> Dict:
        """Generate SARIF 2.1.0 report (v2 — industry standard)."""
        findings = self._flatten_findings(scan_results)
        sarif_results = []
        for i, f in enumerate(findings, 1):
            severity = f.get("calibrated_severity", "INFO")
            sarif_results.append({
                "ruleId": f.get("check", f.get("category", "unknown")),
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                          "LOW": "note", "INFO": "none"}.get(severity, "none"),
                "message": {
                    "text": f.get("reason", f.get("note", f.get("error", "Finding detected")))
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target or "unknown"},
                    }
                }],
                "properties": {
                    "severity": severity,
                    "cvss_v4": self.CVSS_V4_MAP.get(severity, {}),
                    "cvss_v3": self.CVSS_V3_MAP.get(severity, {}),
                    "category": f.get("category"),
                    "evidence": f.get("evidence", "")[:200],
                },
                "partialFingerprints": {"primaryLocationLineHash": f"finding_{i}"},
            })
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "DORAKULA",
                        "version": "3.1.0",
                        "informationUri": "https://github.com/dorakula/dorakula",
                        "rules": [{"id": f.get("check", "default")} for f in findings[:50]],
                    }
                },
                "results": sarif_results,
            }],
        }

    def generate_csv_report(self, scan_results: Dict, target: str = "") -> str:
        """Generate CSV report (v2 — for SIEM import)."""
        findings = self._flatten_findings(scan_results)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["#", "Severity", "Category", "Check", "Description", "CVSS_v4", "CVSS_v3", "Evidence"])
        for i, f in enumerate(findings, 1):
            sev = f.get("calibrated_severity", "INFO")
            writer.writerow([
                i, sev, f.get("category", ""), f.get("check", ""),
                f.get("reason", f.get("note", f.get("error", "")))[:200],
                self.CVSS_V4_MAP.get(sev, {}).get("score", 0),
                self.CVSS_V3_MAP.get(sev, {}).get("score", 0),
                f.get("evidence", "")[:200],
            ])
        return output.getvalue()

    def save_report(self, report_content: str, target: str, format: str = "md") -> str:
        """Save report to file and return path."""
        safe_target = (target or "unknown").replace("://", "_").replace("/", "_").replace(".", "_")[:50]
        filename = f"{self._reports_dir}/dorakula_report_{safe_target}_{int(time.time())}.{format}"
        with open(filename, "w") as f:
            f.write(report_content)
        return filename

    def validate_poc(self, finding: Dict, target: str = "") -> Dict:
        """Validate a finding with safe-by-default PoC (v2)."""
        check = finding.get("check", "")
        validation = "manual_review_required"
        confidence = "LOW"
        # Safe-by-default PoC validation per check type
        if "xss" in check.lower():
            validation = "verify_payload_reflected_in_html"
            confidence = "HIGH" if finding.get("reflected") else "MEDIUM"
        elif "sqli" in check.lower():
            validation = "verify_sql_error_or_time_delay"
            confidence = "HIGH" if finding.get("vulnerable") else "LOW"
        elif "ssrf" in check.lower():
            validation = "verify_metadata_in_response"
            confidence = "HIGH" if finding.get("evidence") else "LOW"
        elif "prompt_injection" in check.lower() or "llm" in check.lower():
            validation = "verify_leaked_content_in_response"
            confidence = "HIGH" if finding.get("potential_leak") else "LOW"
        return {
            "finding": check,
            "target": target,
            "validation": validation,
            "confidence": confidence,
            "calibrated_severity": finding.get("calibrated_severity", "INFO"),
            "note": "Safe-by-default PoC validation — no exploitation performed",
            "version": "v2-2025",
        }
