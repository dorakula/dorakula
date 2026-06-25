#!/usr/bin/env python3
"""DORAKULA CycloneDX VEX Producer — P0 #5 from audit.

VEX (Vulnerability Exploitability eXchange) format for filtering false positives.
CycloneDX VEX is an open standard for communicating exploitability status.
Reference: CycloneDX VEX 1.5 (https://cyclonedx.org/capabilities/vex/)
"""
import json, logging
from typing import Dict, List, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class VEXProducer:
    """Produce CycloneDX VEX documents from DORAKULA findings."""

    VEX_STATUSES = ["exploitable", "in_triage", "resolved", "resolved_with_pedigree", "not_affected"]

    def produce_vex(self, findings: List[Dict], product_name: str = "DORAKULA-Target",
                    product_version: str = "unknown") -> Dict[str, Any]:
        """Convert findings to CycloneDX VEX document."""
        statements = []
        for f in findings:
            vuln_id = f.get("vector", f.get("tool", f.get("cve", "unknown")))
            severity = (f.get("severity", "INFO")).upper()
            # Determine exploitability status
            if severity in ("CRITICAL", "HIGH"):
                status = "exploitable"
            elif severity == "MEDIUM":
                status = "in_triage"
            else:
                status = "not_affected"
            statements.append({
                "vulnerability": {
                    "id": vuln_id,
                    "source": {"name": "DORAKULA", "url": "https://github.com/dorakula/dorakula"},
                    "ratings": [{"severity": severity.lower(), "method": "other"}],
                    "description": f.get("evidence", f.get("description", ""))[:500],
                },
                "status": status,
                "justification": f"Automated assessment: {severity} severity finding by {vuln_id}",
            })
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "type": "vex",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"vendor": "DORAKULA", "name": "VEX Producer", "version": "1.0"}],
                "component": {"type": "application", "name": product_name, "version": product_version},
            },
            "vulnerabilities": statements,
        }

    def to_json(self, findings: List[Dict], **kwargs) -> str:
        return json.dumps(self.produce_vex(findings, **kwargs), indent=2)
