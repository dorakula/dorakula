"""
DORAKULA - Supply Chain Auditor Module
========================================
Advanced supply chain security auditing for bug bounty.
Analyzes JS files, third-party dependencies, CDN configurations,
and detects exposed API keys and outdated vulnerable libraries.

Author: DORAKULA Framework
"""

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

logger = logging.getLogger("dorakula.supply_chain_auditor")


# Known vulnerable library versions (subset for demonstration)
VULNERABLE_LIBS: Dict[str, List[Dict[str, Any]]] = {
    "jquery": [
        {"version_range": "<3.5.0", "cve": "CVE-2020-11022", "severity": "medium",
         "description": "XSS via .html() method"},
        {"version_range": "<3.4.1", "cve": "CVE-2019-11358", "severity": "medium",
         "description": "Prototype pollution via .extend()"},
        {"version_range": "<3.0.0", "cve": "CVE-2015-9251", "severity": "medium",
         "description": "XSS via load() method"},
    ],
    "lodash": [
        {"version_range": "<4.17.21", "cve": "CVE-2021-23337", "severity": "high",
         "description": "Command injection via template"},
        {"version_range": "<4.17.19", "cve": "CVE-2020-8203", "severity": "high",
         "description": "Prototype pollution via zipObjectDeep"},
    ],
    "angular": [
        {"version_range": "<1.8.0", "cve": "CVE-2020-7676", "severity": "high",
         "description": "XSS via animator"},
    ],
    "react": [
        {"version_range": "<16.5.2", "cve": "CVE-2018-6341", "severity": "high",
         "description": "ReDoS vulnerability"},
    ],
    "moment": [
        {"version_range": "<2.29.2", "cve": "CVE-2022-24785", "severity": "high",
         "description": "ReDoS in parse()"},
    ],
    "dompurify": [
        {"version_range": "<2.2.2", "cve": "CVE-2020-26870", "severity": "medium",
         "description": "XSS bypass via nested elements"},
    ],
}

# API key patterns for secret detection
API_KEY_PATTERNS: List[Dict[str, str]] = [
    {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"name": "AWS Secret Key", "pattern": r"(?i)aws(.{0,20})?(?-i)[0-9a-zA-Z/+]{40}", "severity": "critical"},
    {"name": "GitHub Token", "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}", "severity": "critical"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high"},
    {"name": "Google OAuth", "pattern": r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com", "severity": "high"},
    {"name": "Slack Token", "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}", "severity": "critical"},
    {"name": "Slack Webhook", "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9_]{8,}/B[A-Z0-9_]{8,}/[a-zA-Z0-9]{24}", "severity": "high"},
    {"name": "Stripe Secret Key", "pattern": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "critical"},
    {"name": "Stripe Publishable Key", "pattern": r"pk_live_[0-9a-zA-Z]{24,}", "severity": "medium"},
    {"name": "SendGrid API Key", "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "severity": "critical"},
    {"name": "Twilio API Key", "pattern": r"SK[0-9a-fA-F]{32}", "severity": "critical"},
    {"name": "Mailgun API Key", "pattern": r"key-[0-9a-zA-Z]{32}", "severity": "critical"},
    {"name": "Mailchimp API Key", "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}", "severity": "high"},
    {"name": "Firebase URL", "pattern": r"https://[a-z0-9-]+\.firebaseio\.com", "severity": "high"},
    {"name": "Heroku API Key", "pattern": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "severity": "high"},
    {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", "severity": "high"},
    {"name": "Private Key", "pattern": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "severity": "critical"},
    {"name": "Generic Secret", "pattern": r"(?i)(password|secret|token|api_key|apikey|access_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "severity": "high"},
]


class SupplyChainAuditor:
    """Audits web application supply chain security including JS analysis,
    third-party dependencies, CDN integrity, and API key exposure.

    Extracts and analyzes JavaScript files, checks for outdated vulnerable
    libraries, validates Subresource Integrity (SRI), and scans for
    leaked secrets.
    """

    def __init__(self, ai_router: Optional[Any] = None, timeout: int = 30) -> None:
        """Initialize the SupplyChainAuditor.

        Args:
            ai_router: AI router instance for enhanced analysis.
            timeout: Request timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        logger.info("SupplyChainAuditor initialized with timeout=%d", timeout)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session.

        Returns:
            Active aiohttp ClientSession instance.
        """
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
        return self.session

    async def close(self) -> None:
        """Close the aiohttp session and clean up resources."""
        if self.session and not self.session.closed:
            await self.session.close()
            logger.debug("aiohttp session closed")

    async def _fetch_page(self, url: str) -> Tuple[int, str]:
        """Fetch a page and return status code and body.

        Args:
            url: URL to fetch.

        Returns:
            Tuple of (status_code, body_text).
        """
        session = await self._get_session()
        try:
            async with session.get(url) as resp:
                body = await resp.text()
                return resp.status, body
        except aiohttp.ClientError as exc:
            logger.debug("Fetch failed for %s: %s", url, exc)
            return 0, ""

    async def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs from HTML content.

        Args:
            html: HTML content to parse.
            base_url: Base URL for resolving relative paths.

        Returns:
            List of absolute JS file URLs.
        """
        js_urls: List[str] = []
        # Match script src attributes
        patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'<script[^>]+src=([^\s>]+\.js[^\s>]*)',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                absolute_url = urljoin(base_url, match)
                js_urls.append(absolute_url)

        return list(set(js_urls))

    async def _ai_analyze(self, analysis: Dict[str, Any], context: str) -> Dict[str, Any]:
        """Use AI router for enhanced analysis.

        Args:
            analysis: Raw analysis results.
            context: Test type context string.

        Returns:
            AI-enhanced analysis dictionary.
        """
        if self.ai_router is None:
            analysis["ai_analysis"] = "AI router not configured"
            analysis["confidence"] = 0.5
            return analysis

        try:
            prompt = (
                f"Analyze this supply chain audit result for '{context}'. "
                f"Identify critical vulnerabilities and prioritize findings. "
                f"Rate confidence 0.0-1.0. Results: {analysis}"
            )
            ai_result = await self.ai_router.analyze(prompt)
            analysis["ai_analysis"] = ai_result.get("summary", "")
            analysis["confidence"] = ai_result.get("confidence", 0.5)
        except (ConnectionError, TimeoutError, ValueError) as exc:
            logger.warning("AI analysis failed: %s", exc)
            analysis["ai_analysis"] = f"AI analysis error: {exc}"
            analysis["confidence"] = 0.5

        return analysis

    async def audit_js_files(self, target: str) -> Dict[str, Any]:
        """Analyze all JavaScript files for vulnerabilities.

        Extracts JS file URLs from the target page, fetches each file,
        and analyzes them for security issues.

        Args:
            target: Target URL to audit.

        Returns:
            Dictionary with JS file audit results.
        """
        logger.info("Auditing JS files on %s", target)

        try:
            status, html = await self._fetch_page(target)
            if status == 0:
                return {"error": "Failed to fetch target page", "target": target}

            js_urls = await self._extract_js_urls(html, target)
            js_results: List[Dict[str, Any]] = []

            # Fetch and analyze each JS file
            for js_url in js_urls[:50]:  # Limit to 50 files
                js_status, js_content = await self._fetch_page(js_url)
                if js_status == 0 or not js_content:
                    continue

                issues: List[Dict[str, Any]] = []

                # Check for eval usage
                if re.search(r"\beval\s*\(", js_content):
                    issues.append({
                        "type": "eval_usage",
                        "severity": "medium",
                        "description": "Use of eval() detected - potential code injection",
                    })

                # Check for document.write
                if re.search(r"document\.write\s*\(", js_content):
                    issues.append({
                        "type": "document_write",
                        "severity": "medium",
                        "description": "Use of document.write() detected - potential XSS",
                    })

                # Check for innerHTML
                if re.search(r"\.innerHTML\s*=", js_content):
                    issues.append({
                        "type": "inner_html",
                        "severity": "low",
                        "description": "Use of innerHTML assignment detected",
                    })

                # Check for hardcoded URLs
                hardcoded_urls = re.findall(
                    r"https?://[^\s\"'<>]+", js_content
                )
                if len(hardcoded_urls) > 10:
                    issues.append({
                        "type": "hardcoded_urls",
                        "severity": "info",
                        "description": f"{len(hardcoded_urls)} hardcoded URLs found",
                    })

                # Check for comments with sensitive info
                sensitive_comments = re.findall(
                    r"//.*(?i)(password|secret|token|api.key|apikey)",
                    js_content,
                )
                if sensitive_comments:
                    issues.append({
                        "type": "sensitive_comments",
                        "severity": "medium",
                        "description": f"{len(sensitive_comments)} comments with sensitive keywords",
                    })

                js_results.append({
                    "url": js_url,
                    "size": len(js_content),
                    "issues": issues,
                    "issue_count": len(issues),
                })

            total_issues = sum(r["issue_count"] for r in js_results)
            analysis = {
                "target": target,
                "js_files_found": len(js_urls),
                "js_files_analyzed": len(js_results),
                "js_results": js_results,
                "total_issues": total_issues,
                "vulnerable": total_issues > 0,
            }
            analysis = await self._ai_analyze(analysis, "js_file_audit")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("JS audit failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()

    async def audit_third_party(self, target: str) -> Dict[str, Any]:
        """Check third-party dependencies for vulnerabilities.

        Identifies third-party scripts loaded by the target and checks
        their security posture.

        Args:
            target: Target URL to audit.

        Returns:
            Dictionary with third-party dependency audit results.
        """
        logger.info("Auditing third-party dependencies on %s", target)

        try:
            status, html = await self._fetch_page(target)
            if status == 0:
                return {"error": "Failed to fetch target page", "target": target}

            js_urls = await self._extract_js_urls(html, target)
            third_party: List[Dict[str, Any]] = []

            parsed_target = urlparse(target)
            target_domain = parsed_target.hostname or ""

            for js_url in js_urls:
                parsed_js = urlparse(js_url)
                js_domain = parsed_js.hostname or ""

                if js_domain != target_domain:
                    third_party.append({
                        "url": js_url,
                        "domain": js_domain,
                        "is_third_party": True,
                    })

            analysis = {
                "target": target,
                "total_scripts": len(js_urls),
                "third_party_scripts": len(third_party),
                "third_party_details": third_party,
                "vulnerable": len(third_party) > 5,
            }
            analysis = await self._ai_analyze(analysis, "third_party_audit")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("Third-party audit failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()

    async def audit_cdn(self, target: str) -> Dict[str, Any]:
        """Check CDN configuration and integrity.

        Verifies CDN security headers, TLS configuration, and
        cache behavior.

        Args:
            target: Target URL to audit.

        Returns:
            Dictionary with CDN audit results.
        """
        logger.info("Auditing CDN configuration on %s", target)

        try:
            session = await self._get_session()
            async with session.get(target) as resp:
                headers = dict(resp.headers)
                body = await resp.text()

            cdn_indicators: List[str] = []
            cdn_headers = {
                "x-cache": "Cache status header present",
                "x-cdn": "CDN identifier header",
                "cf-ray": "Cloudflare CDN detected",
                "x-amz-cf-id": "AWS CloudFront detected",
                "x-fastly-request-id": "Fastly CDN detected",
                "x-akamai-transformed": "Akamai CDN detected",
                "x-sucuri-id": "Sucuri CDN detected",
                "x-cdn-origin": "CDN origin header",
                "via": "Proxy/CDN via header",
            }

            for header, description in cdn_headers.items():
                if header in {k.lower() for k in headers}:
                    cdn_indicators.append(description)

            # Check for CDN-specific security issues
            issues: List[Dict[str, Any]] = []

            # Check for origin IP exposure
            if "x-origin-ip" in {k.lower() for k in headers}:
                issues.append({
                    "type": "origin_ip_exposure",
                    "severity": "high",
                    "description": "Origin IP exposed via X-Origin-IP header",
                })

            # Check for cache poisoning potential
            if "x-cache" in {k.lower() for k in headers}:
                cache_value = ""
                for k, v in headers.items():
                    if k.lower() == "x-cache":
                        cache_value = v.lower()
                        break
                if "hit" in cache_value:
                    issues.append({
                        "type": "cache_hit",
                        "severity": "medium",
                        "description": "Cache HIT detected - test for cache poisoning",
                    })

            analysis = {
                "target": target,
                "cdn_detected": len(cdn_indicators) > 0,
                "cdn_indicators": cdn_indicators,
                "issues": issues,
                "security_headers": {
                    "strict-transport-security": "strict-transport-security" in {k.lower() for k in headers},
                    "content-security-policy": "content-security-policy" in {k.lower() for k in headers},
                    "x-frame-options": "x-frame-options" in {k.lower() for k in headers},
                },
                "vulnerable": len(issues) > 0,
            }
            analysis = await self._ai_analyze(analysis, "cdn_audit")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("CDN audit failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()

    async def check_sri(self, target: str) -> Dict[str, Any]:
        """Check Subresource Integrity (SRI) usage on the target.

        Verifies whether external scripts use integrity and
        crossorigin attributes to prevent tampering.

        Args:
            target: Target URL to check SRI on.

        Returns:
            Dictionary with SRI check results.
        """
        logger.info("Checking SRI usage on %s", target)

        try:
            status, html = await self._fetch_page(target)
            if status == 0:
                return {"error": "Failed to fetch target page", "target": target}

            js_urls = await self._extract_js_urls(html, target)
            parsed_target = urlparse(target)
            target_domain = parsed_target.hostname or ""

            # Parse script tags for SRI attributes
            script_tags = re.findall(
                r'<script[^>]*>',
                html,
                re.IGNORECASE,
            )

            sri_results: List[Dict[str, Any]] = []
            for tag in script_tags:
                src_match = re.search(r'src=["\']([^"\']+)["\']', tag)
                if not src_match:
                    continue

                src = src_match.group(1)
                has_integrity = "integrity=" in tag.lower()
                has_crossorigin = "crossorigin=" in tag.lower()
                is_external = False

                try:
                    parsed_src = urlparse(src)
                    src_domain = parsed_src.hostname or ""
                    if src_domain and src_domain != target_domain:
                        is_external = True
                except ValueError:
                    pass

                sri_results.append({
                    "src": src,
                    "is_external": is_external,
                    "has_integrity": has_integrity,
                    "has_crossorigin": has_crossorigin,
                    "sri_compliant": has_integrity and has_crossorigin,
                    "vulnerable": is_external and not has_integrity,
                })

            external_without_sri = [
                r for r in sri_results if r["vulnerable"]
            ]

            analysis = {
                "target": target,
                "total_scripts": len(sri_results),
                "external_scripts": sum(1 for r in sri_results if r["is_external"]),
                "sri_protected": sum(1 for r in sri_results if r["sri_compliant"]),
                "external_without_sri": external_without_sri,
                "vulnerable": len(external_without_sri) > 0,
            }
            analysis = await self._ai_analyze(analysis, "sri_check")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("SRI check failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()

    async def check_outdated_libs(self, target: str) -> Dict[str, Any]:
        """Detect outdated and vulnerable JavaScript libraries.

        Identifies library versions from JS file contents and checks
        against known vulnerability databases.

        Args:
            target: Target URL to check for outdated libraries.

        Returns:
            Dictionary with outdated library detection results.
        """
        logger.info("Checking for outdated libraries on %s", target)

        try:
            status, html = await self._fetch_page(target)
            if status == 0:
                return {"error": "Failed to fetch target page", "target": target}

            js_urls = await self._extract_js_urls(html, target)
            detected_libs: List[Dict[str, Any]] = []

            # Version detection patterns
            version_patterns: Dict[str, str] = {
                "jquery": r"jQuery\s+v?([0-9]+\.[0-9]+\.[0-9]+)",
                "lodash": r"Lodash\s+v?([0-9]+\.[0-9]+\.[0-9]+)",
                "angular": r"AngularJS\s+v?([0-9]+\.[0-9]+\.[0-9]+)",
                "react": r"React\s+v?([0-9]+\.[0-9]+\.[0-9]+)",
                "moment": r"Moment\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)",
                "dompurify": r"DOMPurify\s+v?([0-9]+\.[0-9]+\.[0-9]+)",
            }

            for js_url in js_urls[:30]:
                js_status, js_content = await self._fetch_page(js_url)
                if js_status == 0 or not js_content:
                    continue

                for lib_name, pattern in version_patterns.items():
                    match = re.search(pattern, js_content, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        vulnerabilities: List[Dict[str, Any]] = []

                        if lib_name in VULNERABLE_LIBS:
                            for vuln in VULNERABLE_LIBS[lib_name]:
                                version_range = vuln["version_range"]
                                if version_range.startswith("<"):
                                    vuln_version = version_range[1:]
                                    if version < vuln_version:
                                        vulnerabilities.append(vuln)

                        detected_libs.append({
                            "name": lib_name,
                            "version": version,
                            "url": js_url,
                            "vulnerabilities": vulnerabilities,
                            "is_vulnerable": len(vulnerabilities) > 0,
                        })

            vulnerable_libs = [lib for lib in detected_libs if lib["is_vulnerable"]]
            analysis = {
                "target": target,
                "libraries_detected": len(detected_libs),
                "detected_libraries": detected_libs,
                "vulnerable_libraries": vulnerable_libs,
                "vulnerable": len(vulnerable_libs) > 0,
            }
            analysis = await self._ai_analyze(analysis, "outdated_libs_check")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("Outdated libs check failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()

    async def audit_api_keys(self, target: str) -> Dict[str, Any]:
        """Find exposed API keys and secrets in JavaScript files.

        Scans all JS files on the target for known API key patterns
        and secret formats.

        Args:
            target: Target URL to scan for exposed keys.

        Returns:
            Dictionary with API key exposure results.
        """
        logger.info("Scanning for exposed API keys on %s", target)

        try:
            status, html = await self._fetch_page(target)
            if status == 0:
                return {"error": "Failed to fetch target page", "target": target}

            js_urls = await self._extract_js_urls(html, target)
            all_findings: List[Dict[str, Any]] = []

            # Also scan the HTML itself
            sources: List[Dict[str, str]] = [{"url": target, "content": html}]

            # Fetch JS files
            for js_url in js_urls[:50]:
                js_status, js_content = await self._fetch_page(js_url)
                if js_status == 0 or not js_content:
                    continue
                sources.append({"url": js_url, "content": js_content})

            # Scan each source for API keys
            for source in sources:
                content = source["content"]
                source_url = source["url"]

                for key_pattern in API_KEY_PATTERNS:
                    matches = re.findall(key_pattern["pattern"], content)
                    if matches:
                        for match in matches[:5]:  # Limit matches per pattern
                            match_str = str(match)
                            # Truncate for safety
                            display_match = match_str[:20] + "..." if len(match_str) > 20 else match_str
                            all_findings.append({
                                "url": source_url,
                                "type": key_pattern["name"],
                                "severity": key_pattern["severity"],
                                "match": display_match,
                            })

            # Deduplicate findings
            seen: set = set()
            unique_findings: List[Dict[str, Any]] = []
            for finding in all_findings:
                key = f"{finding['url']}:{finding['type']}:{finding['match']}"
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(finding)

            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            unique_findings.sort(
                key=lambda x: severity_order.get(x["severity"], 5)
            )

            analysis = {
                "target": target,
                "files_scanned": len(sources),
                "findings": unique_findings,
                "total_findings": len(unique_findings),
                "critical_findings": sum(
                    1 for f in unique_findings if f["severity"] == "critical"
                ),
                "vulnerable": len(unique_findings) > 0,
            }
            analysis = await self._ai_analyze(analysis, "api_key_audit")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("API key audit failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()
