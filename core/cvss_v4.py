#!/usr/bin/env python3
"""CVSS v4.0 Calculator — P0 #3 from audit."""
import logging, json
from typing import Dict, Any

logger = logging.getLogger(__name__)

class CVSSv4Calculator:
    """CVSS v4.0 calculator with supplemental metrics."""
    ATTACK_VECTOR = {"N": 0.2, "A": 0.22, "L": 0.27, "P": 0.5}
    ATTACK_COMPLEXITY = {"L": 0.2, "H": 0.5}
    ATTACK_REQUIREMENTS = {"N": 0.0, "P": 0.1}
    PRIVILEGES_REQUIRED = {"N": 0.0, "L": 0.1, "H": 0.3}
    USER_INTERACTION = {"N": 0.0, "P": 0.1}
    IMPACT = {"H": 0.6, "L": 0.2, "N": 0.0}
    AUTOMATABLE = {"Y": 1.0, "N": 0.0}
    RECOVERY = {"U": 0.2, "A": 0.0}
    VALUE_DENSITY = {"D": 0.1, "H": 0.2}
    VULN_RESPONSE_EFFORT = {"L": 0.1, "M": 0.0, "H": -0.1}
    PROVIDER_SAFETY = {"P": -0.1, "U": 0.0}
    SEVERITY_BUCKETS = [
        (0.0, 0.0, "NONE"), (0.01, 0.1, "LOW"),
        (0.1, 4.0, "MEDIUM"), (4.0, 7.0, "HIGH"),
        (7.0, 9.0, "CRITICAL"), (9.0, 10.1, "CRITICAL"),
    ]

    def calculate(self, av="N", ac="L", at="N", pr="N", ui="N",
                  vc="H", vi="H", va="H",
                  a="N", r="U", v="D", re="M", ps="U") -> Dict[str, Any]:
        av_s = self.ATTACK_VECTOR.get(av, 0.2)
        ac_s = self.ATTACK_COMPLEXITY.get(ac, 0.2)
        at_s = self.ATTACK_REQUIREMENTS.get(at, 0.0)
        pr_s = self.PRIVILEGES_REQUIRED.get(pr, 0.0)
        ui_s = self.USER_INTERACTION.get(ui, 0.0)
        vc_s = self.IMPACT.get(vc, 0.0)
        vi_s = self.IMPACT.get(vi, 0.0)
        va_s = self.IMPACT.get(va, 0.0)
        exploitability = av_s + ac_s + at_s + pr_s + ui_s
        max_impact = max(vc_s, vi_s, va_s)
        auto_adj = self.AUTOMATABLE.get(a, 0.0)
        recovery_adj = self.RECOVERY.get(r, 0.0)
        value_adj = self.VALUE_DENSITY.get(v, 0.1)
        response_adj = self.VULN_RESPONSE_EFFORT.get(re, 0.0)
        provider_adj = self.PROVIDER_SAFETY.get(ps, 0.0)
        supplemental_adj = auto_adj + recovery_adj + value_adj + response_adj + provider_adj
        base_score = (max_impact + exploitability / 5) * 10
        final_score = min(max(base_score + supplemental_adj, 0.0), 10.0)
        severity = "NONE"
        for low, high, label in self.SEVERITY_BUCKETS:
            if low <= final_score < high:
                severity = label
                break
        vector = (
            f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}"
            f"/VC:{vc}/VI:{vi}/VA:{va}/A:{a}/R:{r}/V:{v}/RE:{re}/PS:{ps}"
        )
        return {
            "version": "4.0",
            "score": round(final_score, 1),
            "severity": severity,
            "vector_string": vector,
            "base_metrics": {
                "attack_vector": av, "attack_complexity": ac,
                "attack_requirements": at, "privileges_required": pr,
                "user_interaction": ui,
                "vuln_confidentiality_impact": vc,
                "vuln_integrity_impact": vi,
                "vuln_availability_impact": va,
            },
            "supplemental_metrics": {
                "automatable": a, "recovery": r, "value_density": v,
                "vulnerability_response_effort": re, "provider_safety": ps,
                "supplemental_adjustment": round(supplemental_adj, 2),
            },
            "reference": "FIRST.org CVSS v4.0 (https://www.first.org/cvss/v4.0)",
        }
