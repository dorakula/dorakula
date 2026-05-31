"""Technology Detector - Detects web technologies from HTTP responses."""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple


logger = logging.getLogger(__name__)


HEADER_SIGNATURES: Dict[str, List[Dict[str, str]]] = {
    "nginx": [{"header": "Server", "pattern": r"(?i)nginx"}],
    "apache": [{"header": "Server", "pattern": r"(?i)apache"}],
    "iis": [{"header": "Server", "pattern": r"(?i)microsoft-iis"}],
    "cloudflare": [{"header": "cf-ray", "pattern": r".+"}, {"header": "Server", "pattern": r"(?i)cloudflare"}],
    "php": [{"header": "X-Powered-By", "pattern": r"(?i)php"}],
    "aspnet": [{"header": "X-Powered-By", "pattern": r"(?i)asp\.net"}, {"header": "X-AspNet-Version", "pattern": r".+"}],
    "express": [{"header": "X-Powered-By", "pattern": r"(?i)express"}],
    "nextjs": [{"header": "X-Powered-By", "pattern": r"(?i)next\.?js"}],
    "django": [{"header": "Set-Cookie", "pattern": r"(?i)csrftoken"}, {"header": "X-Frame-Options", "pattern": r"DENY"}],
    "rails": [{"header": "X-Powered-By", "pattern": r"(?i)phusion passenger"}, {"header": "Set-Cookie", "pattern": r"(?i)_session_id"}],
    "laravel": [{"header": "Set-Cookie", "pattern": r"(?i)laravel_session"}],
    "varnish": [{"header": "X-Varnish", "pattern": r".+"}, {"header": "Via", "pattern": r"(?i)varnish"}],
    "cloudfront": [{"header": "X-Cache", "pattern": r"(?i)(hit|miss)"}, {"header": "Via", "pattern": r"(?i)cloudfront"}],
    "akamai": [{"header": "X-Akamai-Transformed", "pattern": r".+"}, {"header": "X-Cache", "pattern": r"(?i)akamai"}],
}

CONTENT_SIGNATURES: Dict[str, List[Dict[str, str]]] = {
    "wordpress": [
        {"pattern": r"(?i)wp-content", "confidence": "high"},
        {"pattern": r"(?i)wp-includes", "confidence": "high"},
        {"pattern": r"<meta\s+name=\"generator\"\s+content=\"WordPress", "confidence": "high"},
    ],
    "joomla": [
        {"pattern": r"(?i)/media/jui/", "confidence": "high"},
        {"pattern": r"<meta\s+name=\"generator\"\s+content=\"Joomla", "confidence": "high"},
    ],
    "drupal": [
        {"pattern": r"(?i)sites/default/files", "confidence": "high"},
        {"pattern": r"(?i)Drupal\.settings", "confidence": "high"},
        {"pattern": r"<meta\s+name=\"Generator\"\s+content=\"Drupal", "confidence": "high"},
    ],
    "react": [
        {"pattern": r"(?i)data-reactroot", "confidence": "high"},
        {"pattern": r"(?i)__NEXT_DATA__", "confidence": "medium"},
        {"pattern": r"(?i)react\.createElement", "confidence": "medium"},
    ],
    "vue": [
        {"pattern": r"(?i)data-v-[a-f0-9]+", "confidence": "high"},
        {"pattern": r"(?i)__vue__", "confidence": "high"},
        {"pattern": r"(?i)vue\.component", "confidence": "medium"},
    ],
    "angular": [
        {"pattern": r"(?i)ng-version", "confidence": "high"},
        {"pattern": r"(?i)ng-app", "confidence": "medium"},
        {"pattern": r"(?i)angular\.module", "confidence": "medium"},
    ],
    "jquery": [
        {"pattern": r"(?i)jquery[.-]\d+\.\d+", "confidence": "high"},
        {"pattern": r"(?i)jquery\.min\.js", "confidence": "medium"},
    ],
    "bootstrap": [
        {"pattern": r"(?i)bootstrap\.(min\.)?(css|js)", "confidence": "high"},
        {"pattern": r"(?i)class=\"[^\"]*col-(xs|sm|md|lg)", "confidence": "medium"},
    ],
    "tailwind": [
        {"pattern": r"(?i)class=\"[^\"]*(?:flex|grid|bg-|text-|p-|m-|w-|h-)(?:-|\s)", "confidence": "low"},
    ],
    "laravel": [
        {"pattern": r"(?i)laravel_session", "confidence": "high"},
        {"pattern": r"(?i)csrf-token.*laravel", "confidence": "medium"},
    ],
    "shopify": [
        {"pattern": r"(?i)shopify\.cdn", "confidence": "high"},
        {"pattern": r"(?i)Shopify\.theme", "confidence": "high"},
    ],
    "magento": [
        {"pattern": r"(?i)mage\.cookies", "confidence": "high"},
        {"pattern": r"(?i)skin/frontend", "confidence": "medium"},
    ],
    "git_exposed": [
        {"pattern": r"(?i)\.git/config", "confidence": "high"},
        {"pattern": r"(?i)\.git/HEAD", "confidence": "high"},
    ],
}


class TechnologyDetector:
    """Detects web technologies from HTTP responses."""

    def __init__(self, ai_router: Any):
        self.ai_router = ai_router
        self.detected: Dict[str, List[Dict[str, Any]]] = {}

    def detect(
        self,
        response_headers: Dict[str, str],
        response_body: str,
        url: str = ""
    ) -> Dict[str, Any]:
        """Detect technologies from HTTP response headers and body."""
        detected_techs: List[Dict[str, Any]] = []
        seen: set = set()

        # Header-based detection
        for tech_name, signatures in HEADER_SIGNATURES.items():
            for sig in signatures:
                header_name = sig["header"]
                pattern = sig["pattern"]
                header_value = response_headers.get(header_name, "")
                if header_value and re.search(pattern, header_value):
                    if tech_name not in seen:
                        seen.add(tech_name)
                        version = self._extract_version(tech_name, header_value)
                        detected_techs.append({
                            "name": tech_name,
                            "source": "header",
                            "evidence": f"{header_name}: {header_value[:100]}",
                            "confidence": "high",
                            "version": version,
                        })

        # Content-based detection
        for tech_name, signatures in CONTENT_SIGNATURES.items():
            for sig in signatures:
                pattern = sig["pattern"]
                confidence = sig.get("confidence", "medium")
                if re.search(pattern, response_body):
                    if tech_name not in seen:
                        seen.add(tech_name)
                        detected_techs.append({
                            "name": tech_name,
                            "source": "content",
                            "evidence": f"Pattern matched: {pattern[:80]}",
                            "confidence": confidence,
                            "version": None,
                        })

        # Security header analysis
        security_headers = self._analyze_security_headers(response_headers)

        result = {
            "url": url,
            "technologies": detected_techs,
            "security_headers": security_headers,
            "tech_count": len(detected_techs),
        }

        self.detected[url] = detected_techs
        logger.info(f"Detected {len(detected_techs)} technologies for {url}")
        return result

    def _extract_version(self, tech_name: str, header_value: str) -> Optional[str]:
        """Extract version number from header value."""
        version_patterns = {
            "nginx": r"nginx/([\d.]+)",
            "apache": r"Apache/([\d.]+)",
            "iis": r"Microsoft-IIS/([\d.]+)",
            "php": r"PHP/([\d.]+)",
            "aspnet": r"ASP\.NET(?:/)?([\d.]*)",
            "express": r"Express(?:/)?([\d.]*)",
        }
        pattern = version_patterns.get(tech_name)
        if pattern:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security-related headers."""
        important_headers = {
            "Strict-Transport-Security": {"present": False, "value": ""},
            "Content-Security-Policy": {"present": False, "value": ""},
            "X-Content-Type-Options": {"present": False, "value": ""},
            "X-Frame-Options": {"present": False, "value": ""},
            "X-XSS-Protection": {"present": False, "value": ""},
            "Referrer-Policy": {"present": False, "value": ""},
            "Permissions-Policy": {"present": False, "value": ""},
        }

        for header_name in important_headers:
            if header_name in headers:
                important_headers[header_name]["present"] = True
                important_headers[header_name]["value"] = headers[header_name]

        missing = [h for h, v in important_headers.items() if not v["present"]]
        score = len(important_headers) - len(missing)

        return {
            "headers": important_headers,
            "missing_headers": missing,
            "security_score": f"{score}/{len(important_headers)}",
        }
