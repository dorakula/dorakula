#!/usr/bin/env python3
"""Dorakula CJK-Native Vulnerability Research
Encoding-specific vulnerability detection for CJK software.
Unique competitive advantage - no Western tool has this.
"""
import logging
import asyncio
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class CJKVulnResearch:
    """Research vulnerabilities specific to CJK software ecosystems"""
    
    ENCODING_PATTERNS = {
        "gbk_injection": {
            "encodings": ["gbk", "gb2312", "gb18030"],
            "patterns": [r"%bf%27", r"%bf%5c", r"%a1%27", r"\x bf\x27"],
            "frameworks": ["ThinkPHP", "DedeCMS", "PHPCMS"],
            "databases": ["MySQL GBK", "SQL Server GBK"]
        },
        "shift_jis_bypass": {
            "encodings": ["shift_jis", "cp932", "euc-jp"],
            "patterns": [r"%81%27", r"%81%5c", r"\x81\x27"],
            "frameworks": ["Ruby on Rails (Shift-JIS)", "CakePHP (Shift-JIS)"],
            "databases": ["MySQL Shift-JIS", "PostgreSQL EUC-JP"]
        },
        "euc_kr_injection": {
            "encodings": ["euc-kr", "cp949"],
            "patterns": [r"%a1%27", r"%a1%5c"],
            "frameworks": ["Spring Boot (EUC-KR)", "Django CJK"],
            "databases": ["MySQL EUC-KR"]
        }
    }
    
    CJK_CVE_SOURCES = {
        "cnvd": {"url": "https://www.cnvd.org.cn", "country": "China", "focus": "Chinese software"},
        "jvn": {"url": "https://jvn.jp", "country": "Japan", "focus": "Japanese software"},
        "krvd": {"url": "https://www.kisa.or.kr", "country": "Korea", "focus": "Korean software"}
    }
    
    CJK_FRAMEWORKS = {
        "ThinkPHP": {"versions": ["5.x", "6.x", "8.x"], "common_vulns": ["RCE", "SQLi", "LFI"], "cve_prefix": "CNVD"},
        "DedeCMS": {"versions": ["5.7", "5.8"], "common_vulns": ["RCE", "XSS", "file_upload"], "cve_prefix": "CNVD"},
        "PHPCMS": {"versions": ["9.x"], "common_vulns": ["SQLi", "XSS", "RCE"], "cve_prefix": "CNVD"},
        "Struts2": {"versions": ["2.x"], "common_vulns": ["RCE", "OGNL injection"], "cve_prefix": "CVE"},
        "Spring Boot CJK": {"versions": ["2.x", "3.x"], "common_vulns": ["SSRF", "SpEL injection"], "cve_prefix": "CVE"},
    }
    
    def __init__(self, ai_router=None):
        self.ai_router = ai_router
    
    def detect_encoding_vulns(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Detect encoding-specific vulnerabilities"""
        detected = []
        encoding = target_info.get("encoding", "").lower()
        
        for vuln_type, config in self.ENCODING_PATTERNS.items():
            if encoding in config["encodings"]:
                detected.append({
                    "vulnerability_type": vuln_type,
                    "affected_encodings": config["encodings"],
                    "patterns": config["patterns"],
                    "affected_frameworks": config["frameworks"],
                    "affected_databases": config["databases"],
                    "severity": "high"
                })
        
        return {"success": True, "encoding_vulns": detected, "target_encoding": encoding}
    
    def identify_cjk_framework(self, response_headers: Dict, response_body: str) -> Dict[str, Any]:
        """Identify CJK-specific frameworks"""
        detected = []
        framework_signatures = {
            "ThinkPHP": ["thinkphp", "think\_", "X-Powered-By: ThinkPHP"],
            "DedeCMS": ["dedecms", "powerby", "dede"],
            "PHPCMS": ["phpcms", "php\_base"],
        }
        
        for framework, sigs in framework_signatures.items():
            for sig in sigs:
                if sig.lower() in response_body.lower() or any(sig.lower() in str(v).lower() for v in response_headers.values()):
                    info = self.CJK_FRAMEWORKS.get(framework, {})
                    detected.append({"framework": framework, "info": info})
                    break
        
        return {"success": True, "detected_frameworks": detected}
    
    async def research_cjk_cves(self, keywords: List[str], sources: List[str] = None) -> Dict[str, Any]:
        """Research CVEs from CJK databases"""
        results = []
        
        if self.ai_router:
            result = await self.ai_router.chat([
                {"role": "system", "content": "You are a CJK vulnerability researcher. Search for vulnerabilities in Chinese, Japanese, and Korean software."},
                {"role": "user", "content": f"Search for CJK vulnerabilities related to: {keywords}\nSources: {sources or list(self.CJK_CVE_SOURCES.keys())}\n\nReturn JSON with: cves, recommendations, affected_software"}
            ])
            if result.get("success"):
                results.append({"source": "ai_research", "data": result.get("content", "")})
        
        return {"success": True, "results": results, "sources_queried": sources or list(self.CJK_CVE_SOURCES.keys())}
