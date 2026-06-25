#!/usr/bin/env python3
"""DORAKULA AI False Positive Reduction Engine — P0 #8 from audit.

Target: 99.6% accuracy (ScienceDirect 2025 study benchmark).
Expands slop_detector with advanced ML-like patterns.

Reference: HackerOne Hai Triage (AI agentic FP filtering, 90% adoption)
"""
import logging, json, re
from typing import Dict, List, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class FPReductionEngine:
    """Advanced false positive reduction with multi-signal scoring."""

    # Signal weights (higher = stronger indicator of true positive)
    SIGNAL_WEIGHTS = {
        "payload_reflected": 30,      # payload reflected in response
        "sql_error_in_response": 35, # SQL syntax error visible
        "status_code_anomaly": 15,   # unexpected status code
        "timing_difference": 25,     # measurable time difference
        "response_size_diff": 10,    # response size changed
        "header_anomaly": 10,        # security header missing/changed
        "error_message_leak": 20,    # internal error message leaked
        "file_content_visible": 40,  # actual file content returned
        "command_output": 45,        # command execution output visible
        "redirect_to_external": 25,  # open redirect confirmed
        "cookie_set": 15,           # new cookie set by response
    }

    # Negative signals (indicators of false positive)
    FP_SIGNALS = {
        "connection_error": -50,
        "timeout_only": -30,
        "dns_failure": -40,
        "generic_error_page": -20,
        "no_response_diff": -15,
        "placeholder_content": -25,
        "example_domain": -10,
    }

    def reduce_false_positives(self, findings: List[Dict]) -> Dict[str, Any]:
        """Process findings list and reduce false positives."""
        processed = []
        rejected = []
        for f in findings:
            score = self._calculate_confidence(f)
            f["fp_confidence_score"] = score
            f["fp_verdict"] = (
                "confirmed" if score >= 70
                else "likely_true" if score >= 50
                else "uncertain" if score >= 30
                else "likely_false_positive" if score >= 10
                else "false_positive"
            )
            if score >= 30:
                processed.append(f)
            else:
                rejected.append(f)
        return {
            "status": "success",
            "tool": "fp_reduction_engine",
            "input_count": len(findings),
            "confirmed_count": len(processed),
            "rejected_count": len(rejected),
            "rejection_rate": round(100 * len(rejected) / max(len(findings), 1), 1),
            "processed_findings": processed,
            "rejected_findings": rejected,
            "target_accuracy": "99.6% (ScienceDirect 2025)",
        }

    def _calculate_confidence(self, finding: Dict) -> int:
        """Calculate confidence score (0-100) for a finding."""
        # ponytail FIX#16: use input confidence as starting score (if provided)
        # Input confidence is 0.0-1.0, scale to 0-100
        input_conf = finding.get("confidence")
        if isinstance(input_conf, (int, float)):
            if input_conf <= 1.0:  # 0.0-1.0 range
                score = int(input_conf * 100)
            else:  # already 0-100 range
                score = int(input_conf)
        else:
            score = 50  # neutral start if no confidence provided
        evidence = str(finding.get("evidence", "")).lower()
        severity = finding.get("severity", "INFO").upper()
        # Positive signals
        if finding.get("poc_curl") or finding.get("poc"):
            score += self.SIGNAL_WEIGHTS["payload_reflected"]
        if any(k in evidence for k in ["sql", "syntax", "mysql", "oracle"]):
            score += self.SIGNAL_WEIGHTS["sql_error_in_response"]
        if finding.get("reflected"):
            score += self.SIGNAL_WEIGHTS["payload_reflected"]
        if "uid=" in evidence or "root:" in evidence:
            score += self.SIGNAL_WEIGHTS["command_output"]
        if "redirect" in evidence or "location:" in evidence:
            score += self.SIGNAL_WEIGHTS["redirect_to_external"]
        if any(k in evidence for k in ["file", "passwd", "etc/"]):
            score += self.SIGNAL_WEIGHTS["file_content_visible"]
        if finding.get("timing_diff", 0) > 2:
            score += self.SIGNAL_WEIGHTS["timing_difference"]
        # Negative signals
        if "connection" in evidence and ("refused" in evidence or "reset" in evidence):
            score += self.FP_SIGNALS["connection_error"]
        if "timeout" in evidence and not finding.get("poc"):
            score += self.FP_SIGNALS["timeout_only"]
        if "nxdomain" in evidence or "name resolution" in evidence:
            score += self.FP_SIGNALS["dns_failure"]
        if "example.com" in str(finding.get("pinpoint_url", "")):
            score += self.FP_SIGNALS["example_domain"]
        if not evidence.strip():
            score += self.FP_SIGNALS["no_response_diff"]
        # Severity bonus
        if severity == "CRITICAL":
            score += 10
        elif severity == "HIGH":
            score += 5
        return max(0, min(100, score))
