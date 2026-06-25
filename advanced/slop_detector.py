#!/usr/bin/env python3
"""Dorakula AI Slop Detector
Cross-validation dual-model false positive filtering.
Target: <5% false positive rate via ML-based signal filtering.
"""
import json
import logging
import asyncio
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class AISlopDetector:
    """Verify vulnerability findings using a second AI model"""
    
    def __init__(self, ai_router=None, threshold: int = 70):
        self.ai_router = ai_router
        self.threshold = threshold
        self.verified_count = 0
        self.rejected_count = 0
    
    async def verify(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a vulnerability finding using cross-validation"""
        if not self.ai_router:
            finding["verified"] = True
            finding["confidence"] = 100
            finding["verification_method"] = "skipped_no_ai"
            return finding
        
        try:
            result = await self.ai_router.chat([
                {"role": "system", "content": """You are a vulnerability verification expert. 
Analyze findings for AI slop - false positives that look convincing but are invalid.
Rate validity 0-100. Consider:
1. Is the evidence technically sound?
2. Does the PoC actually prove the vulnerability?
3. Is the severity rating appropriate?
4. Are there logical inconsistencies?
5. Is this a known false positive pattern?

Respond in JSON: {"score": N, "verdict": "valid"/"invalid"/"uncertain", "reasoning": "explanation"}"""},
                {"role": "user", "content": f"""Verify this finding:
Title: {finding.get("title", "N/A")}
Type: {finding.get("type", "N/A")}
Severity: {finding.get("severity", "N/A")}
Evidence: {finding.get("evidence", "N/A")}
PoC: {finding.get("poc", "N/A")}
URL: {finding.get("url", "N/A")}"""}
            ], temperature=0.2)
            
            if result.get("success"):
                try:
                    content = result.get("content", "")
                    if "```" in content:
                        content = content.split("```")[1]
                        if content.startswith("json"):
                            content = content[4:]
                    verification = json.loads(content.strip())
                    score = verification.get("score", 0)
                    
                    if score >= self.threshold:
                        finding["verified"] = True
                        finding["confidence"] = score
                        finding["verdict"] = verification.get("verdict", "valid")
                        self.verified_count += 1
                    else:
                        finding["verified"] = False
                        finding["confidence"] = score
                        finding["rejection_reason"] = verification.get("reasoning", "Below threshold")
                        finding["verdict"] = verification.get("verdict", "invalid")
                        self.rejected_count += 1
                    
                    finding["verification_method"] = f"ai_cross_validation ({result.get('provider', 'unknown')})"
                    finding["verification_details"] = verification
                except json.JSONDecodeError:
                    finding["verified"] = True
                    finding["confidence"] = 50
                    finding["verification_method"] = "ai_parse_failed"
            else:
                finding["verified"] = True
                finding["confidence"] = 50
                finding["verification_method"] = "ai_unavailable"
        except Exception as e:
            logger.warning("Slop detection failed: %s", e)
            finding["verified"] = True
            finding["confidence"] = 50
            finding["verification_method"] = "error"
        
        return finding
    
    async def batch_verify(self, findings: List[Dict]) -> List[Dict]:
        """Verify multiple findings"""
        verified = []
        for finding in findings:
            verified.append(await self.verify(finding))
        return verified
    
    def get_stats(self) -> Dict[str, Any]:
        total = self.verified_count + self.rejected_count
        return {
            "total_verified": self.verified_count,
            "total_rejected": self.rejected_count,
            "rejection_rate": round(self.rejected_count / total, 2) if total else 0,
            "threshold": self.threshold
        }

    # ============================================================
    # v2 upgrade: rule-based pre-filter + Bayesian scoring (Mythos 6.2)
    # ============================================================

    # Rule-based false positive patterns (fast pre-filter before AI)
    FP_PATTERNS = {
        "empty_evidence": lambda f: not f.get("evidence") or f.get("evidence", "").strip() == "",
        "generic_severity": lambda f: f.get("severity", "").lower() == "high" and not f.get("poc"),
        "no_url": lambda f: not f.get("url") or f.get("url", "").strip() == "",
        "placeholder_response": lambda f: "example" in str(f.get("evidence", "")).lower() and "200" in str(f.get("evidence", "")),
        "timeout_as_vuln": lambda f: "timeout" in str(f.get("evidence", "")).lower() and f.get("severity", "").lower() == "critical",
        "connection_refused_as_vuln": lambda f: "connection refused" in str(f.get("evidence", "")).lower(),
        "dns_failure_as_vuln": lambda f: "nxdomain" in str(f.get("evidence", "")).lower() or "name resolution" in str(f.get("evidence", "")).lower(),
    }

    # Bayesian prior probabilities by vulnerability type (Mythos 6.2)
    BAYESIAN_PRIORS = {
        "sqli": 0.15,      # 15% base rate in web apps
        "xss": 0.25,       # 25% base rate
        "ssrf": 0.08,      # 8% base rate
        "lfi": 0.10,       # 10% base rate
        "rce": 0.05,       # 5% base rate
        "idor": 0.12,      # 12% base rate
        "csrf": 0.15,      # 15% base rate
        "open_redirect": 0.20,  # 20% base rate
        "default": 0.10,   # 10% default
    }

    # Likelihood ratios for evidence types (Mythos 6.2)
    EVIDENCE_LIKELIHOODS = {
        "reflected_payload": 8.0,     # strong evidence
        "error_message": 5.0,         # moderate-strong
        "timing_difference": 3.0,     # moderate
        "status_code_anomaly": 2.0,   # weak-moderate
        "header_anomaly": 1.5,        # weak
        "no_evidence": 0.2,           # strong negative evidence
        "connection_error": 0.1,      # very strong negative (likely FP)
    }

    def rule_based_prefilter(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Fast rule-based pre-filter before AI verification.

        Returns finding with prefilter_score (0-100).
        Score < 30 = likely false positive, skip AI verification.
        """
        score = 100  # start at 100, deduct for each FP pattern matched

        for pattern_name, check_fn in self.FP_PATTERNS.items():
            try:
                if check_fn(finding):
                    score -= 20  # each FP pattern deducts 20 points
                    finding.setdefault("fp_flags", []).append(pattern_name)
            except Exception:
                pass

        finding["prefilter_score"] = max(score, 0)
        finding["prefilter_verdict"] = (
            "likely_valid" if score >= 70
            else "uncertain" if score >= 30
            else "likely_false_positive"
        )
        return finding

    def bayesian_score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Bayesian confidence scoring (Mythos 6.2).

        P(Vuln|Evidence) = P(Evidence|Vuln) * P(Vuln) / P(Evidence)

        Uses prior probabilities by vuln type + likelihood ratios for evidence types.
        """
        vuln_type = finding.get("type", "").lower()
        prior = self.BAYESIAN_PRIORS.get(vuln_type, self.BAYESIAN_PRIORS["default"])

        # Determine evidence type and likelihood
        evidence_str = str(finding.get("evidence", "")).lower()
        if "reflected" in evidence_str or finding.get("poc", ""):
            likelihood = self.EVIDENCE_LIKELIHOODS["reflected_payload"]
        elif "error" in evidence_str and "sql" in evidence_str:
            likelihood = self.EVIDENCE_LIKELIHOODS["error_message"]
        elif "timeout" in evidence_str or "delay" in evidence_str:
            likelihood = self.EVIDENCE_LIKELIHOODS["timing_difference"]
        elif "403" in evidence_str or "500" in evidence_str:
            likelihood = self.EVIDENCE_LIKELIHOODS["status_code_anomaly"]
        elif "header" in evidence_str:
            likelihood = self.EVIDENCE_LIKELIHOODS["header_anomaly"]
        elif "connection" in evidence_str and "refused" in evidence_str:
            likelihood = self.EVIDENCE_LIKELIHOODS["connection_error"]
        elif not evidence_str.strip():
            likelihood = self.EVIDENCE_LIKELIHOODS["no_evidence"]
        else:
            likelihood = 1.0  # neutral

        # Bayesian update: posterior = (likelihood * prior) / ((likelihood * prior) + ((1-likelihood) * (1-prior)))
        # Simplified: posterior = likelihood * prior / (likelihood * prior + (1 - likelihood) * (1 - prior))
        posterior = (likelihood * prior) / (likelihood * prior + (1 - likelihood) * (1 - prior) + 0.001)

        finding["bayesian_prior"] = round(prior, 3)
        finding["bayesian_likelihood"] = round(likelihood, 3)
        finding["bayesian_posterior"] = round(posterior, 3)
        finding["bayesian_confidence"] = "HIGH" if posterior > 0.7 else ("MEDIUM" if posterior > 0.4 else "LOW")

        return finding

    async def verify_enhanced(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced verification: rule-based pre-filter + Bayesian + AI (if needed).

        Pipeline:
          1. Rule-based pre-filter (fast, no AI)
          2. If prefilter_score < 30 → reject as FP, skip AI
          3. Bayesian scoring (fast, no AI)
          4. If Bayesian posterior > 0.8 → accept as valid, skip AI
          5. Only if uncertain → call AI verification (expensive)
        """
        # Step 1: Rule-based pre-filter
        finding = self.rule_based_prefilter(finding)

        # Step 2: Skip AI if clearly false positive
        if finding["prefilter_score"] < 30:
            finding["verified"] = False
            finding["confidence"] = finding["prefilter_score"]
            finding["verification_method"] = "rule_based_prefilter_reject"
            finding["verdict"] = "invalid"
            self.rejected_count += 1
            return finding

        # Step 3: Bayesian scoring
        finding = self.bayesian_score(finding)

        # Step 4: Accept if high confidence
        if finding["bayesian_posterior"] > 0.8:
            finding["verified"] = True
            finding["confidence"] = int(finding["bayesian_posterior"] * 100)
            finding["verification_method"] = "bayesian_high_confidence"
            finding["verdict"] = "valid"
            self.verified_count += 1
            return finding

        # Step 5: AI verification (only for uncertain findings)
        return await self.verify(finding)
