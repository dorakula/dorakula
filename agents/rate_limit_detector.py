"""Rate Limit Detector - Detects rate limiting from HTTP responses."""

import logging
import re
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class RateLimitDetector:
    """Detects rate limiting mechanisms from HTTP responses."""

    def __init__(self, ai_router: Any):
        self.ai_router = ai_router
        self.detection_history: List[Dict[str, Any]] = []

    def detect(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str = "",
        request_count: int = 0
    ) -> Dict[str, Any]:
        """Detect rate limiting from HTTP response signals."""
        signals: List[Dict[str, Any]] = []

        # Status code detection
        if status_code == 429:
            signals.append({
                "type": "status_code",
                "indicator": "429 Too Many Requests",
                "confidence": "high",
                "detail": "Explicit rate limit response",
            })
        elif status_code == 503:
            signals.append({
                "type": "status_code",
                "indicator": "503 Service Unavailable",
                "confidence": "medium",
                "detail": "May indicate rate limiting or server overload",
            })
        elif status_code == 403 and request_count > 5:
            signals.append({
                "type": "status_code",
                "indicator": "403 Forbidden (after multiple requests)",
                "confidence": "medium",
                "detail": "Possible rate limit via access denial",
            })

        # Header-based detection
        rate_limit_headers = {
            "X-RateLimit-Limit": {"type": "rate_limit_header", "meaning": "Maximum requests allowed"},
            "X-RateLimit-Remaining": {"type": "rate_limit_header", "meaning": "Requests remaining"},
            "X-RateLimit-Reset": {"type": "rate_limit_header", "meaning": "Reset timestamp"},
            "Retry-After": {"type": "retry_header", "meaning": "Seconds until rate limit resets"},
            "X-Rate-Limit-Limit": {"type": "rate_limit_header", "meaning": "Maximum requests (alt)"},
            "X-Rate-Limit-Remaining": {"type": "rate_limit_header", "meaning": "Remaining requests (alt)"},
            "X-Rate-Limit-Reset": {"type": "rate_limit_header", "meaning": "Reset time (alt)"},
            "RateLimit-Limit": {"type": "rate_limit_header", "meaning": "IETF draft standard limit"},
            "RateLimit-Remaining": {"type": "rate_limit_header", "meaning": "IETF draft remaining"},
            "RateLimit-Reset": {"type": "rate_limit_header", "meaning": "IETF draft reset"},
        }

        for header_name, header_info in rate_limit_headers.items():
            if header_name in headers:
                signals.append({
                    "type": header_info["type"],
                    "indicator": header_name,
                    "confidence": "high",
                    "detail": f"{header_info['meaning']}: {headers[header_name]}",
                    "value": headers[header_name],
                })

        # Cloudflare-specific
        cf_headers = {k: v for k, v in headers.items() if k.lower().startswith("cf-")}
        if cf_headers:
            for h, v in cf_headers.items():
                if "limit" in h.lower() or "retry" in h.lower():
                    signals.append({
                        "type": "cloudflare_header",
                        "indicator": h,
                        "confidence": "high",
                        "detail": f"Cloudflare rate limit: {v}",
                        "value": v,
                    })

        # Body-based detection
        if body:
            body_lower = body.lower()
            rate_limit_keywords = [
                (r"rate\s*limit", "Rate limit message in response body"),
                (r"too\s*many\s*requests", "Too many requests message"),
                (r"slow\s*down", "Slow down message in response body"),
                (r"try\s*again\s*(?:in|after)\s+\d+", "Retry-after message in body"),
                (r"request\s*throttl", "Throttling message in body"),
                (r"api\s*usage\s*exceeded", "API usage exceeded message"),
                (r"quota\s*exceeded", "Quota exceeded message"),
                (r"rate\s*exceeded", "Rate exceeded message"),
            ]
            for pattern, description in rate_limit_keywords:
                if re.search(pattern, body_lower):
                    signals.append({
                        "type": "body_content",
                        "indicator": description,
                        "confidence": "medium",
                        "detail": f"Pattern '{pattern}' found in response body",
                    })
                    break

        # Determine overall detection
        is_rate_limited = (
            status_code == 429
            or any(s["type"] == "rate_limit_header" for s in signals)
            or (status_code in (403, 503) and any(s["type"] == "body_content" for s in signals))
        )

        # Extract rate limit info
        rate_limit_info = self._extract_rate_limit_info(signals)

        # Calculate recommended wait
        retry_after = headers.get("Retry-After")
        wait_seconds = self._calculate_wait(retry_after, signals)

        result = {
            "is_rate_limited": is_rate_limited,
            "signals": signals,
            "signal_count": len(signals),
            "rate_limit_info": rate_limit_info,
            "recommended_wait_seconds": wait_seconds,
            "status_code": status_code,
        }

        self.detection_history.append(result)
        if is_rate_limited:
            logger.warning(f"Rate limit detected: {len(signals)} signals, wait {wait_seconds}s")
        else:
            logger.info(f"No rate limit detected (status: {status_code})")

        return result

    def _extract_rate_limit_info(self, signals: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract structured rate limit information from signals."""
        info: Dict[str, Any] = {"limit": None, "remaining": None, "reset": None}
        for signal in signals:
            if signal.get("type") != "rate_limit_header":
                continue
            indicator = signal.get("indicator", "").lower()
            value = signal.get("value")
            if "limit" in indicator and "remaining" not in indicator and "reset" not in indicator:
                try:
                    info["limit"] = int(value)
                except (ValueError, TypeError):
                    info["limit"] = value
            elif "remaining" in indicator:
                try:
                    info["remaining"] = int(value)
                except (ValueError, TypeError):
                    info["remaining"] = value
            elif "reset" in indicator:
                info["reset"] = value
        return info

    def _calculate_wait(
        self, retry_after: Optional[str], signals: List[Dict[str, Any]]
    ) -> int:
        """Calculate recommended wait time in seconds."""
        if retry_after:
            try:
                return int(retry_after)
            except (ValueError, TypeError):
                pass

        for signal in signals:
            if signal.get("type") == "retry_header":
                try:
                    return int(signal.get("value", 60))
                except (ValueError, TypeError):
                    pass

        if any(s.get("indicator") == "429 Too Many Requests" for s in signals):
            return 60

        if any(s.get("type") == "body_content" for s in signals):
            return 30

        return 0
