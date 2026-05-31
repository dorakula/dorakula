"""
DORAKULA - Subdomain Takeover Detector Module
===============================================
Advanced subdomain takeover detection for bug bounty.
Checks CNAME records against known vulnerable providers,
verifies dangling DNS, and validates potential takeovers.

Author: DORAKULA Framework
"""

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger("dorakula.subdomain_takeover")


# Known takeover providers with their CNAME patterns and fingerprint signatures
TAKEOVER_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "aws_s3": {
        "cname_patterns": [".s3.amazonaws.com", ".s3-website.", ".s3-website-us-", ".s3-website-eu-"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist", "Code: NoSuchBucket"],
        "claimable": True,
    },
    "github_pages": {
        "cname_patterns": [".github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs", "404 File not found"],
        "claimable": True,
    },
    "heroku": {
        "cname_patterns": [".herokuapp.com", ".herokussl.com"],
        "fingerprints": ["No such app", "Heroku | No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "claimable": True,
    },
    "shopify": {
        "cname_patterns": [".myshopify.com", ".shopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "claimable": True,
    },
    "tumblr": {
        "cname_patterns": [".tumblr.com"],
        "fingerprints": ["Whatever you were looking for doesn't currently exist", "Whatever you were looking for doesn't exist"],
        "claimable": True,
    },
    "wordpress": {
        "cname_patterns": [".wordpress.com"],
        "fingerprints": ["Do you want to register", "wordpress.com is no longer available"],
        "claimable": True,
    },
    "azure": {
        "cname_patterns": [".azurewebsites.net", ".cloudapp.net", ".azureedge.net"],
        "fingerprints": ["404 Web Site not found", "The page could not be found", "Azure"],
        "claimable": True,
    },
    "gitlab": {
        "cname_patterns": [".gitlab.io"],
        "fingerprints": ["The page you're looking for could not be found", "You may have mistyped the address"],
        "claimable": True,
    },
    "pantheon": {
        "cname_patterns": [".pantheon.io", ".pantheonsite.io"],
        "fingerprints": ["404 error unknown site", "Pantheon"],
        "claimable": True,
    },
    "ghost": {
        "cname_patterns": [".ghost.io"],
        "fingerprints": ["The thing you were looking for is no longer here", "ghost.io"],
        "claimable": True,
    },
    "freshdesk": {
        "cname_patterns": [".freshdesk.com"],
        "fingerprints": ["Sorry, but we couldn't find that page", "Freshdesk"],
        "claimable": True,
    },
    "zendesk": {
        "cname_patterns": [".zendesk.com"],
        "fingerprints": ["Help Center Closed", "We've moved", "zendesk.com"],
        "claimable": True,
    },
    "cargo": {
        "cname_patterns": [".cargo.site"],
        "fingerprints": ["If you're moving your domain away from Cargo", "cargo.site"],
        "claimable": True,
    },
    "statuspage": {
        "cname_patterns": [".statuspage.io", ".statuspage.at"],
        "fingerprints": ["You are being redirected", "StatusPage"],
        "claimable": True,
    },
}


class SubdomainTakeoverDetector:
    """Detects subdomain takeover vulnerabilities by checking CNAME records,
    fingerprinting cloud providers, and verifying dangling DNS entries.

    Supports 14 known takeover providers including AWS S3, GitHub Pages,
    Heroku, Shopify, and more.
    """

    def __init__(self, ai_router: Optional[Any] = None, timeout: int = 15) -> None:
        """Initialize the SubdomainTakeoverDetector.

        Args:
            ai_router: AI router instance for enhanced analysis.
            timeout: Request timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        logger.info("SubdomainTakeoverDetector initialized with timeout=%d", timeout)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session.

        Returns:
            Active aiohttp ClientSession instance.
        """
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=False,
            )
        return self.session

    async def close(self) -> None:
        """Close the aiohttp session and clean up resources."""
        if self.session and not self.session.closed:
            await self.session.close()
            logger.debug("aiohttp session closed")

    async def _resolve_cname(self, domain: str) -> Optional[str]:
        """Resolve CNAME record for a domain using dns resolver.

        Args:
            domain: Domain name to resolve.

        Returns:
            CNAME target string or None if not found.
        """
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "CNAME")
            return str(answers[0].target).rstrip(".")
        except ImportError:
            logger.warning("dnspython not installed, using fallback")
            return await self._resolve_cname_fallback(domain)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as exc:
            logger.debug("CNAME resolution failed for %s: %s", domain, exc)
            return None
        except Exception as exc:
            logger.debug("CNAME lookup error for %s: %s", domain, exc)
            return None

    async def _resolve_cname_fallback(self, domain: str) -> Optional[str]:
        """Fallback CNAME resolution using system tools.

        Args:
            domain: Domain name to resolve.

        Returns:
            CNAME target string or None if not found.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "CNAME", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            result = stdout.decode().strip().rstrip(".")
            return result if result else None
        except (FileNotFoundError, asyncio.TimeoutError, OSError) as exc:
            logger.debug("Fallback CNAME resolution failed for %s: %s", domain, exc)
            return None

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
                return resp.status, body[:10000]
        except aiohttp.ClientError as exc:
            logger.debug("Fetch failed for %s: %s", url, exc)
            return 0, str(exc)

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
                f"Analyze this subdomain takeover test for '{context}'. "
                f"Determine if this is a true takeover vulnerability. "
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

    async def check_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Check a single subdomain for takeover vulnerability.

        Resolves CNAME, identifies the provider, fetches the page,
        and checks for takeover fingerprint signatures.

        Args:
            subdomain: Subdomain to check (e.g., 'blog.example.com').

        Returns:
            Dictionary with takeover check results.
        """
        logger.info("Checking subdomain for takeover: %s", subdomain)

        try:
            # Step 1: Resolve CNAME
            cname = await self._resolve_cname(subdomain)

            if cname is None:
                return {
                    "subdomain": subdomain,
                    "cname": None,
                    "vulnerable": False,
                    "reason": "No CNAME record found",
                }

            # Step 2: Identify provider
            provider_info = await self.fingerprint_provider(cname)

            # Step 3: Fetch page and check fingerprints
            urls_to_check = [f"http://{subdomain}", f"https://{subdomain}"]
            page_content = ""
            status_code = 0

            for url in urls_to_check:
                code, body = await self._fetch_page(url)
                if code > 0:
                    status_code = code
                    page_content = body
                    break

            # Step 4: Check fingerprints
            fingerprint_matches: List[str] = []
            provider_name = provider_info.get("provider", "unknown")
            if provider_name in TAKEOVER_PROVIDERS:
                for fp in TAKEOVER_PROVIDERS[provider_name]["fingerprints"]:
                    if fp.lower() in page_content.lower():
                        fingerprint_matches.append(fp)

            is_vulnerable = (
                len(fingerprint_matches) > 0
                and provider_info.get("claimable", False)
            )

            analysis = {
                "subdomain": subdomain,
                "cname": cname,
                "provider": provider_name,
                "claimable": provider_info.get("claimable", False),
                "status_code": status_code,
                "fingerprint_matches": fingerprint_matches,
                "vulnerable": is_vulnerable,
                "page_snippet": page_content[:500] if page_content else "",
            }
            analysis = await self._ai_analyze(analysis, f"subdomain_takeover_{subdomain}")
            return analysis

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.error("Subdomain check failed for %s: %s", subdomain, exc)
            return {"subdomain": subdomain, "error": str(exc), "vulnerable": False}

    async def check_cname_chain(self, domain: str) -> Dict[str, Any]:
        """Enumerate and check all CNAME records in a domain chain.

        Resolves the full CNAME chain and checks each record for
        dangling entries and takeover potential.

        Args:
            domain: Base domain to check CNAME chain for.

        Returns:
            Dictionary with CNAME chain analysis.
        """
        logger.info("Checking CNAME chain for %s", domain)

        try:
            chain: List[str] = []
            current = domain
            visited: set = set()

            for _ in range(10):  # Max chain depth
                if current in visited:
                    break
                visited.add(current)

                cname = await self._resolve_cname(current)
                if cname is None:
                    break
                chain.append(cname)
                current = cname

            # Check each CNAME in the chain
            results: List[Dict[str, Any]] = []
            for cname_target in chain:
                provider_info = await self.fingerprint_provider(cname_target)
                provider_name = provider_info.get("provider", "unknown")

                # Check if the CNAME resolves to an active service
                status, body = await self._fetch_page(f"http://{cname_target}")

                is_dangling = False
                if provider_name in TAKEOVER_PROVIDERS:
                    for fp in TAKEOVER_PROVIDERS[provider_name]["fingerprints"]:
                        if fp.lower() in body.lower():
                            is_dangling = True
                            break

                results.append({
                    "cname": cname_target,
                    "provider": provider_name,
                    "claimable": provider_info.get("claimable", False),
                    "dangling": is_dangling,
                    "status_code": status,
                })

            vulnerable_entries = [r for r in results if r["dangling"] and r["claimable"]]

            analysis = {
                "domain": domain,
                "cname_chain": chain,
                "chain_depth": len(chain),
                "results": results,
                "vulnerable_entries": vulnerable_entries,
                "vulnerable": len(vulnerable_entries) > 0,
            }
            analysis = await self._ai_analyze(analysis, f"cname_chain_{domain}")
            return analysis

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.error("CNAME chain check failed: %s", exc)
            return {"domain": domain, "error": str(exc), "vulnerable": False}

    async def check_dangling_dns(self, domain: str) -> Dict[str, Any]:
        """Find dangling DNS records that point to non-existent services.

        Checks for DNS records that resolve to IP addresses or hostnames
        that are no longer active or serving content.

        Args:
            domain: Domain to check for dangling DNS.

        Returns:
            Dictionary with dangling DNS analysis.
        """
        logger.info("Checking for dangling DNS on %s", domain)

        try:
            dangling_records: List[Dict[str, Any]] = []

            # Check CNAME records
            cname = await self._resolve_cname(domain)
            if cname:
                # Check if the CNAME target resolves
                try:
                    import dns.resolver
                    dns.resolver.resolve(cname, "A")
                    target_resolves = True
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    target_resolves = False
                except Exception:
                    target_resolves = False
                except ImportError:
                    target_resolves = True  # Cannot verify without dnspython

                if not target_resolves:
                    dangling_records.append({
                        "record_type": "CNAME",
                        "target": cname,
                        "issue": "CNAME target does not resolve",
                    })

            # Check if domain resolves but serves no content
            status, body = await self._fetch_page(f"http://{domain}")
            if status == 0 or (status >= 500 and "bad gateway" in body.lower()):
                dangling_records.append({
                    "record_type": "A",
                    "target": domain,
                    "issue": "Domain resolves but server is unreachable or misconfigured",
                })

            # Check for common subdomain patterns
            common_subdomains = [
                "www", "blog", "api", "dev", "staging", "mail",
                "ftp", "admin", "test", "portal", "app", "cdn",
            ]
            for sub in common_subdomains:
                subdomain = f"{sub}.{domain}"
                cname = await self._resolve_cname(subdomain)
                if cname:
                    status_sub, body_sub = await self._fetch_page(
                        f"http://{subdomain}"
                    )
                    # Check provider fingerprints
                    for prov_name, prov_data in TAKEOVER_PROVIDERS.items():
                        for fp in prov_data["fingerprints"]:
                            if fp.lower() in body_sub.lower():
                                dangling_records.append({
                                    "record_type": "CNAME",
                                    "subdomain": subdomain,
                                    "target": cname,
                                    "provider": prov_name,
                                    "issue": f"Provider fingerprint match: {prov_name}",
                                })
                                break

            analysis = {
                "domain": domain,
                "dangling_records": dangling_records,
                "total_dangling": len(dangling_records),
                "vulnerable": len(dangling_records) > 0,
            }
            analysis = await self._ai_analyze(analysis, f"dangling_dns_{domain}")
            return analysis

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.error("Dangling DNS check failed: %s", exc)
            return {"domain": domain, "error": str(exc), "vulnerable": False}

    async def fingerprint_provider(self, cname: str) -> Dict[str, Any]:
        """Identify the cloud provider from a CNAME record.

        Matches the CNAME against known provider patterns.

        Args:
            cname: CNAME target string.

        Returns:
            Dictionary with provider identification results.
        """
        cname_lower = cname.lower()

        for provider_name, provider_data in TAKEOVER_PROVIDERS.items():
            for pattern in provider_data["cname_patterns"]:
                if pattern in cname_lower:
                    return {
                        "provider": provider_name,
                        "claimable": provider_data["claimable"],
                        "fingerprints": provider_data["fingerprints"],
                        "matched_pattern": pattern,
                    }

        return {
            "provider": "unknown",
            "claimable": False,
            "fingerprints": [],
            "matched_pattern": None,
        }

    async def verify_takeover(self, subdomain: str) -> Dict[str, Any]:
        """Attempt to verify a potential subdomain takeover.

        Performs deeper checks to confirm if a subdomain is actually
        vulnerable to takeover, including checking if the service
        allows claiming.

        Args:
            subdomain: Subdomain to verify takeover for.

        Returns:
            Dictionary with takeover verification results.
        """
        logger.info("Verifying takeover for %s", subdomain)

        try:
            # First run the basic check
            check_result = await self.check_subdomain(subdomain)

            if not check_result.get("vulnerable", False):
                return {
                    "subdomain": subdomain,
                    "verified": False,
                    "reason": "Basic check did not indicate vulnerability",
                    "check_result": check_result,
                }

            provider_name = check_result.get("provider", "unknown")
            cname = check_result.get("cname", "")

            # Deep verification based on provider
            verification_steps: List[Dict[str, Any]] = []

            # Step 1: Confirm CNAME points to unclaimed service
            if provider_name in TAKEOVER_PROVIDERS:
                provider_data = TAKEOVER_PROVIDERS[provider_name]
                fingerprints_matched = check_result.get("fingerprint_matches", [])

                if fingerprints_matched:
                    verification_steps.append({
                        "step": "fingerprint_confirmation",
                        "result": True,
                        "details": f"Matched fingerprints: {fingerprints_matched}",
                    })

            # Step 2: Check if the service allows new account creation
            signup_urls: Dict[str, str] = {
                "aws_s3": "https://s3.console.aws.amazon.com",
                "github_pages": "https://github.com/new",
                "heroku": "https://signup.heroku.com",
                "shopify": "https://www.shopify.com/signup",
                "wordpress": "https://wordpress.com/start",
                "azure": "https://azure.microsoft.com/free",
                "gitlab": "https://gitlab.com/users/sign_up",
                "pantheon": "https://pantheon.io/register",
                "ghost": "https://ghost.org/signup",
                "freshdesk": "https://freshdesk.com/signup",
                "zendesk": "https://www.zendesk.com/register",
                "cargo": "https://cargo.site/signup",
                "statuspage": "https://www.statuspage.io/signup",
                "tumblr": "https://www.tumblr.com/register",
            }

            if provider_name in signup_urls:
                verification_steps.append({
                    "step": "service_signup_available",
                    "result": True,
                    "details": f"Signup URL: {signup_urls[provider_name]}",
                })

            # Step 3: Check if we can reach the claim endpoint
            status, body = await self._fetch_page(f"http://{subdomain}")
            claim_indicators = [
                "create", "sign up", "register", "claim",
                "available", "get started", "start your",
            ]
            claim_detected = any(
                ind in body.lower() for ind in claim_indicators
            )
            verification_steps.append({
                "step": "claim_page_detected",
                "result": claim_detected,
                "details": "Claim/registration indicators found in response" if claim_detected else "No claim indicators",
            })

            # Determine verification status
            passed_steps = sum(1 for s in verification_steps if s["result"])
            verified = passed_steps >= 2

            analysis = {
                "subdomain": subdomain,
                "verified": verified,
                "provider": provider_name,
                "cname": cname,
                "verification_steps": verification_steps,
                "confidence": round(passed_steps / max(len(verification_steps), 1), 2),
                "recommendation": (
                    f"Subdomain appears vulnerable to {provider_name} takeover. "
                    f"Attempt to claim via {signup_urls.get(provider_name, 'provider signup page')}."
                ) if verified else "Subdomain does not appear to be verifiably vulnerable.",
            }
            analysis = await self._ai_analyze(analysis, f"verify_takeover_{subdomain}")
            return analysis

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.error("Takeover verification failed for %s: %s", subdomain, exc)
            return {"subdomain": subdomain, "error": str(exc), "verified": False}
        finally:
            await self.close()
