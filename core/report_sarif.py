#!/usr/bin/env python3
"""DORAKULA SARIF 2.1.0 Output Module — P0 #2 from audit.

SARIF (Static Analysis Results Interchange Format) 2.1.0 is the OASIS standard
supported by GitHub Code Scanning, Azure DevOps, SonarCloud, DefectDojo.

This module converts DORAKULA scan findings to SARIF 2.1.0 JSON format,
enabling CI/CD pipeline integration and import into security platforms.

Reference: OASIS SARIF 2.1.0 (https://docs.oasis-is.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
"""
import json, logging, hashlib
from typing import Dict, List, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class SARIFReporter:
    """Convert DORAKULA findings to SARIF 2.1.0 format."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

    # Severity → SARIF level mapping
    SEVERITY_TO_LEVEL = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none",
    }

    # CVSS v3.1 to SARIF properties mapping
    def convert_findings(self, findings: List[Dict], target: str = "",
                         tool_version: str = "3.1.0") -> Dict[str, Any]:
        """Convert DORAKULA findings list to SARIF 2.1.0 JSON.

        Args:
            findings: List of finding dicts (from scan_target/auto_pilot_exploit)
            target: Target URL/hostname
            tool_version: DORAKULA version string

        Returns:
            SARIF 2.1.0 compliant JSON dict
        """
        # Build rules from unique finding types
        rules_map = {}
        rules = []
        rule_index = 0

        for f in findings:
            rule_id = f.get("vector", f.get("tool", f.get("type", "unknown")))
            if rule_id not in rules_map:
                severity = (f.get("severity", "INFO")).upper()
                rules_map[rule_id] = rule_index
                rules.append({
                    "id": rule_id,
                    "name": rule_id.replace("_", " ").title(),
                    "shortDescription": {
                        "text": f.get("description", f"DORAKULA finding: {rule_id}")[:200]
                    },
                    "fullDescription": {
                        "text": f.get("evidence", f.get("description", ""))[:1000]
                    },
                    "defaultLevel": self.SEVERITY_TO_LEVEL.get(severity, "note"),
                    "helpUri": f"https://dorakula.github.io/rules/{rule_id}",
                    "properties": {
                        "severity": severity,
                        "tags": ["security", "DORAKULA", rule_id],
                    },
                })
                rule_index += 1

        # Build results
        results = []
        for f in findings:
            rule_id = f.get("vector", f.get("tool", f.get("type", "unknown")))
            rule_idx = rules_map.get(rule_id, 0)
            severity = (f.get("severity", "INFO")).upper()
            pinpoint_url = f.get("pinpoint_url", f.get("url", target))

            result = {
                "ruleId": rule_id,
                "ruleIndex": rule_idx,
                "level": self.SEVERITY_TO_LEVEL.get(severity, "note"),
                "message": {
                    "text": f.get("evidence", f.get("description", f"{rule_id} finding"))[:1000]
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": pinpoint_url or target or "unknown",
                        },
                    }
                }],
                "properties": {
                    "severity": severity,
                    "tool": f.get("vector", f.get("tool", "")),
                    "poc": f.get("poc_curl", ""),
                    "category": f.get("category", ""),
                },
                "partialFingerprints": {
                    "primaryLocationLineHash": hashlib.sha256(
                        f"{rule_id}:{pinpoint_url}:{severity}".encode()
                    ).hexdigest()[:16],
                },
            }
            results.append(result)

        # Build SARIF document
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "DORAKULA",
                        "version": tool_version,
                        "informationUri": "https://github.com/dorakula/dorakula",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                    "toolExecutionSuccessful": True,
                }],
            }],
        }

        return sarif

    def to_json(self, findings: List[Dict], target: str = "",
                tool_version: str = "3.1.0", indent: int = 2) -> str:
        """Convert findings to SARIF JSON string."""
        sarif = self.convert_findings(findings, target, tool_version)
        return json.dumps(sarif, indent=indent, ensure_ascii=False)

    def to_file(self, findings: List[Dict], filepath: str,
                target: str = "", tool_version: str = "3.1.0") -> str:
        """Convert findings to SARIF and save to file."""
        json_str = self.to_json(findings, target, tool_version)
        with open(filepath, "w") as f:
            f.write(json_str)
        return filepath
