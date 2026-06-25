#!/usr/bin/env python3
"""Dorakula Auto-Remediation Engine
AI-generated patches and WAF rules for automated remediation.
"""
import json
import logging
import asyncio
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class AutoRemediationEngine:
    """Generate remediation code for discovered vulnerabilities"""
    
    def __init__(self, ai_router=None):
        self.ai_router = ai_router
        self.remediation_templates = {
            "sqli": {"language": "python", "fix": "Use parameterized queries"},
            "xss": {"language": "javascript", "fix": "Implement output encoding"},
            "ssrf": {"language": "python", "fix": "Implement URL whitelist validation"},
            "lfi": {"language": "php", "fix": "Validate and sanitize file paths"},
            "rce": {"language": "python", "fix": "Avoid shell execution with user input"},
        }
    
    async def generate_remediation(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate specific remediation code for a vulnerability"""
        vuln_type = vulnerability.get("type", "").lower()
        target_lang = vulnerability.get("language", "auto-detect")
        
        if self.ai_router:
            result = await self.ai_router.chat([
                {"role": "system", "content": """You are a security remediation expert. Generate SPECIFIC, WORKING fix code.
For each vulnerability provide:
1. Root cause analysis
2. Specific fix code (not generic advice)
3. Unit test to verify the fix
4. WAF rule as temporary mitigation
5. Priority level

Return as JSON: {root_cause, fix_code, fix_language, unit_test, waf_rule, priority}"""},
                {"role": "user", "content": f"Generate remediation for:\nType: {vuln_type}\nDetails: {json.dumps(vulnerability, indent=2)}\nTarget language: {target_lang}"}
            ], temperature=0.2)
            
            if result.get("success"):
                try:
                    content = result.get("content", "")
                    if "```" in content:
                        content = content.split("```")[1]
                        if content.startswith("json"):
                            content = content[4:]
                    remediation = json.loads(content.strip())
                    return {
                        "success": True,
                        "vuln_type": vuln_type,
                        "remediation": remediation,
                        "provider": result.get("provider", ""),
                        "ai_generated": True
                    }
                except json.JSONDecodeError:
                    return {
                        "success": True,
                        "vuln_type": vuln_type,
                        "remediation": {"raw_response": result.get("content", "")},
                        "ai_generated": True
                    }
        
        # Fallback
        template = self.remediation_templates.get(vuln_type, {"fix": "Review and validate all user inputs"})
        return {"success": True, "vuln_type": vuln_type, "remediation": template, "ai_generated": False}
    
    async def batch_remediate(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate remediation for multiple vulnerabilities"""
        results = []
        for vuln in vulnerabilities:
            result = await self.generate_remediation(vuln)
            results.append(result)
        return results
