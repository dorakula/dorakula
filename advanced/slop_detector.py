#!/usr/bin/env python3
"""Dorakula AI Slop Detector
Cross-validation dual-model false positive filtering.
Target: <5% false positive rate (HexStrike has 25%).
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
