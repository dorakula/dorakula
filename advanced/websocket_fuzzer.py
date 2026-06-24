#!/usr/bin/env python3
"""DORAKULA WebSocket & Real-Time Protocol Fuzzer.

Connection handshake fuzzing, message frame fuzzing, injection tests.
"""
import logging, json, random, string
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

try:
    import websocket as ws_lib
    HAS_WS = True
except ImportError:
    HAS_WS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class WebSocketFuzzer:
    """Fuzzer for WebSocket connections and messages."""

    INJECTION_PAYLOADS = [
        "<script>alert(1)</script>",
        "'; DROP TABLE users; --",
        "$(whoami)",
        "{{7*7}}",
        "../../etc/passwd",
        "\\x00\\x01\\x02",
        "A" * 10000,  # Large payload
        "{invalid json}",
        None,  # None type
        12345,  # Integer
    ]

    def __init__(self):
        self._results = []

    def test_handshake(self, target: str) -> Dict:
        """Test WebSocket handshake for issues."""
        findings = []
        if HAS_REQUESTS:
            # Test upgrade header manipulation
            headers_tests = [
                {"Upgrade": "websocket", "Connection": "Upgrade"},  # Standard
                {"Upgrade": "WebSocket", "Connection": "Upgrade"},  # Case variation
                {"Upgrade": "websocket", "Connection": "upgrade, keep-alive"},  # Extra
                {},  # Missing headers
            ]
            for i, headers in enumerate(headers_tests):
                try:
                    ws_url = target.replace("http", "ws", 1) if target.startswith("http") else target
                    if HAS_WS:
                        ws = ws_lib.create_connection(ws_url, timeout=5, header=headers)
                        findings.append({
                            "test": f"handshake_variant_{i}",
                            "success": True,
                            "severity": "INFO",
                        })
                        ws.close()
                except Exception as e:
                    findings.append({
                        "test": f"handshake_variant_{i}",
                        "success": False,
                        "error": str(e)[:100],
                        "severity": "LOW",
                    })
        return {"check": "handshake", "target": target, "findings": findings}

    def test_message_injection(self, target: str) -> Dict:
        """Send injection payloads via WebSocket messages."""
        findings = []
        if not HAS_WS:
            return {"error": "websocket-client not available"}
        ws_url = target.replace("http", "ws", 1) if target.startswith("http") else target
        try:
            ws = ws_lib.create_connection(ws_url, timeout=10)
            for payload in self.INJECTION_PAYLOADS:
                try:
                    if payload is None:
                        ws.send("null")
                    elif isinstance(payload, int):
                        ws.send(str(payload))
                    else:
                        ws.send(str(payload))
                    response = ws.recv()
                    # Check if payload reflected in response (potential XSS/injection)
                    reflected = str(payload)[:50] in str(response)[:500] if payload else False
                    findings.append({
                        "payload_type": type(payload).__name__,
                        "payload_snippet": str(payload)[:50] if payload else "null",
                        "response_snippet": str(response)[:200],
                        "reflected": reflected,
                        "severity": "HIGH" if reflected else "INFO",
                    })
                except Exception as e:
                    findings.append({
                        "payload_type": type(payload).__name__,
                        "error": str(e)[:100],
                    })
            ws.close()
        except Exception as e:
            return {"error": f"Connection failed: {str(e)[:200]}"}
        return {
            "check": "message_injection",
            "target": target,
            "findings": findings,
            "total_payloads": len(self.INJECTION_PAYLOADS),
        }

    def test_connection_flood(self, target: str, num_connections: int = 20) -> Dict:
        """Test for DoS via connection flooding."""
        if not HAS_WS:
            return {"error": "websocket-client not available"}
        ws_url = target.replace("http", "ws", 1) if target.startswith("http") else target
        connections = []
        successful = 0
        for i in range(num_connections):
            try:
                ws = ws_lib.create_connection(ws_url, timeout=3)
                connections.append(ws)
                successful += 1
            except Exception:
                break
        # Cleanup
        for ws in connections:
            try:
                ws.close()
            except Exception:
                pass
        return {
            "check": "connection_flood",
            "target": target,
            "attempted": num_connections,
            "successful_connections": successful,
            "severity": "HIGH" if successful == num_connections else ("MEDIUM" if successful > 5 else "LOW"),
        }

    def full_scan(self, target: str) -> Dict:
        """Run all WebSocket fuzzing tests."""
        return {
            "target": target,
            "handshake": self.test_handshake(target),
            "message_injection": self.test_message_injection(target),
            "connection_flood": self.test_connection_flood(target),
        }
