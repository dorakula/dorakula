"""
DORAKULA - Race Condition Detector Module
==========================================
Advanced race condition and TOCTOU vulnerability detection for bug bounty.
Uses asyncio + aiohttp for high-concurrency request racing with AI-enhanced
false positive filtering.

Author: DORAKULA Framework
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger("dorakula.race_condition")


class RaceConditionDetector:
    """Detects race condition vulnerabilities by sending concurrent requests
    and comparing results against single-request baselines.

    This module tests for TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
    including coupon reuse, balance transfer races, vote manipulation, and
    rate limit bypasses.
    """

    def __init__(self, ai_router: Optional[Any] = None, timeout: int = 30) -> None:
        """Initialize the RaceConditionDetector.

        Args:
            ai_router: AI router instance for enhanced analysis and false
                positive filtering.
            timeout: Request timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        logger.info("RaceConditionDetector initialized with timeout=%d", timeout)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session.

        Returns:
            Active aiohttp ClientSession instance.
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

    async def _send_single_request(
        self,
        url: str,
        method: str = "POST",
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Send a single HTTP request and return structured result.

        Args:
            url: Target URL.
            method: HTTP method.
            json_data: JSON payload for the request.
            headers: Optional HTTP headers.

        Returns:
            Dictionary with status_code, body, headers, and elapsed time.
        """
        session = await self._get_session()
        start = time.monotonic()
        try:
            async with session.request(
                method, url, json=json_data, headers=headers
            ) as resp:
                body = await resp.text()
                elapsed = time.monotonic() - start
                return {
                    "status_code": resp.status,
                    "body": body[:5000],
                    "headers": dict(resp.headers),
                    "elapsed": elapsed,
                }
        except aiohttp.ClientError as exc:
            elapsed = time.monotonic() - start
            logger.warning("Request to %s failed: %s", url, exc)
            return {
                "status_code": None,
                "body": str(exc),
                "headers": {},
                "elapsed": elapsed,
                "error": True,
            }

    async def _send_race_requests(
        self,
        url: str,
        method: str = "POST",
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
        concurrency: int = 50,
    ) -> List[Dict[str, Any]]:
        """Send multiple concurrent requests to test race conditions.

        Args:
            url: Target URL.
            method: HTTP method.
            json_data: JSON payload for each request.
            headers: Optional HTTP headers.
            concurrency: Number of concurrent requests.

        Returns:
            List of response dictionaries from each request.
        """
        tasks = [
            self._send_single_request(url, method, json_data, headers)
            for _ in range(concurrency)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        processed: List[Dict[str, Any]] = []
        for result in results:
            if isinstance(result, Exception):
                processed.append(
                    {"status_code": None, "body": str(result), "error": True}
                )
            else:
                processed.append(result)
        return processed

    def _analyze_race_results(
        self,
        single_result: Dict[str, Any],
        race_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Analyze race condition results by comparing single vs concurrent.

        Args:
            single_result: Result from a single request.
            race_results: Results from concurrent requests.

        Returns:
            Analysis dictionary with vulnerability indicators.
        """
        race_status_codes = [
            r.get("status_code") for r in race_results if r.get("status_code")
        ]
        race_bodies = [r.get("body", "") for r in race_results]

        # Count distinct status codes
        status_counts: Dict[Optional[int], int] = {}
        for code in race_status_codes:
            status_counts[code] = status_counts.get(code, 0) + 1

        # Check for status code divergence
        single_status = single_result.get("status_code")
        divergence = len(status_counts) > 1 or (
            single_status not in status_counts and len(status_counts) > 0
        )

        # Check for response body differences among race results
        unique_bodies = len(set(race_bodies)) if race_bodies else 0

        # Detect successful responses that differ from the single request
        success_count = sum(1 for c in race_status_codes if c and 200 <= c < 300)

        # Calculate timing statistics
        race_times = [r.get("elapsed", 0) for r in race_results]
        avg_time = sum(race_times) / len(race_times) if race_times else 0
        min_time = min(race_times) if race_times else 0

        return {
            "single_status": single_status,
            "race_status_counts": status_counts,
            "status_code_divergence": divergence,
            "unique_response_bodies": unique_bodies,
            "success_count_in_race": success_count,
            "total_race_requests": len(race_results),
            "avg_response_time": round(avg_time, 4),
            "min_response_time": round(min_time, 4),
            "potential_vulnerability": divergence or unique_bodies > 1,
        }

    async def _ai_analyze(self, analysis: Dict[str, Any], context: str) -> Dict[str, Any]:
        """Use AI router to filter false positives and provide insight.

        Args:
            analysis: Raw analysis results.
            context: Context string describing the test type.

        Returns:
            AI-enhanced analysis with confidence scoring.
        """
        if self.ai_router is None:
            analysis["ai_analysis"] = "AI router not configured"
            analysis["confidence"] = 0.5
            return analysis

        try:
            prompt = (
                f"Analyze this race condition test result for '{context}'. "
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

    async def test_race_condition(
        self,
        target: str,
        endpoint: str,
        method: str = "POST",
        concurrency: int = 50,
    ) -> Dict[str, Any]:
        """Test a generic endpoint for race condition vulnerabilities.

        Sends a single request as baseline, then fires concurrent requests
        and compares the results for inconsistencies.

        Args:
            target: Base URL of the target (e.g., 'https://example.com').
            endpoint: API endpoint path (e.g., '/api/transfer').
            method: HTTP method to use.
            concurrency: Number of concurrent requests.

        Returns:
            Dictionary with race condition test results and analysis.
        """
        url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
        logger.info("Testing race condition on %s with concurrency=%d", url, concurrency)

        try:
            single_result = await self._send_single_request(url, method)
            race_results = await self._send_race_requests(
                url, method, concurrency=concurrency
            )
            analysis = self._analyze_race_results(single_result, race_results)
            analysis["url"] = url
            analysis["method"] = method
            analysis = await self._ai_analyze(analysis, "generic_race_condition")
            return analysis
        except aiohttp.ClientError as exc:
            logger.error("Race condition test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}
        finally:
            await self.close()

    async def test_coupon_race(self, target: str, coupon: str) -> Dict[str, Any]:
        """Test coupon code reuse via race condition.

        Fires concurrent coupon apply requests to exploit the window
        between validation and redemption.

        Args:
            target: Base URL of the target application.
            coupon: Coupon code to test for reuse.

        Returns:
            Dictionary with coupon race test results.
        """
        url = f"{target.rstrip('/')}/api/coupon/apply"
        payload = {"coupon": coupon}
        logger.info("Testing coupon race on %s with coupon=%s", url, coupon)

        try:
            single_result = await self._send_single_request(
                url, "POST", json_data=payload
            )
            race_results = await self._send_race_requests(
                url, "POST", json_data=payload, concurrency=50
            )
            analysis = self._analyze_race_results(single_result, race_results)
            analysis["url"] = url
            analysis["test_type"] = "coupon_race"
            analysis["coupon"] = coupon

            # Count successful applies in race
            success_applies = sum(
                1 for r in race_results
                if r.get("status_code") == 200
                and "success" in r.get("body", "").lower()
            )
            analysis["successful_applies"] = success_applies
            analysis["coupon_reuse_detected"] = success_applies > 1
            analysis = await self._ai_analyze(analysis, "coupon_race")
            return analysis
        except aiohttp.ClientError as exc:
            logger.error("Coupon race test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}
        finally:
            await self.close()

    async def test_transfer_race(self, target: str, amount: float) -> Dict[str, Any]:
        """Test balance transfer race condition.

        Sends concurrent transfer requests to detect if the same funds
        can be transferred multiple times.

        Args:
            target: Base URL of the target application.
            amount: Transfer amount to test with.

        Returns:
            Dictionary with transfer race test results.
        """
        url = f"{target.rstrip('/')}/api/transfer"
        payload = {"amount": amount, "recipient": "test_account"}
        logger.info("Testing transfer race on %s with amount=%.2f", url, amount)

        try:
            single_result = await self._send_single_request(
                url, "POST", json_data=payload
            )
            race_results = await self._send_race_requests(
                url, "POST", json_data=payload, concurrency=50
            )
            analysis = self._analyze_race_results(single_result, race_results)
            analysis["url"] = url
            analysis["test_type"] = "transfer_race"
            analysis["amount"] = amount

            # Detect multiple successful transfers
            success_transfers = sum(
                1 for r in race_results if r.get("status_code") == 200
            )
            analysis["successful_transfers"] = success_transfers
            analysis["double_spend_detected"] = success_transfers > 1
            analysis = await self._ai_analyze(analysis, "transfer_race")
            return analysis
        except aiohttp.ClientError as exc:
            logger.error("Transfer race test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}
        finally:
            await self.close()

    async def test_vote_race(self, target: str, vote_id: str) -> Dict[str, Any]:
        """Test voting system race condition for vote multiplication.

        Fires concurrent vote requests to detect if a single user
        can cast multiple votes.

        Args:
            target: Base URL of the target application.
            vote_id: ID of the vote/poll to test.

        Returns:
            Dictionary with vote race test results.
        """
        url = f"{target.rstrip('/')}/api/vote"
        payload = {"vote_id": vote_id, "choice": 1}
        logger.info("Testing vote race on %s with vote_id=%s", url, vote_id)

        try:
            single_result = await self._send_single_request(
                url, "POST", json_data=payload
            )
            race_results = await self._send_race_requests(
                url, "POST", json_data=payload, concurrency=50
            )
            analysis = self._analyze_race_results(single_result, race_results)
            analysis["url"] = url
            analysis["test_type"] = "vote_race"
            analysis["vote_id"] = vote_id

            success_votes = sum(
                1 for r in race_results if r.get("status_code") == 200
            )
            analysis["successful_votes"] = success_votes
            analysis["vote_multiplication_detected"] = success_votes > 1
            analysis = await self._ai_analyze(analysis, "vote_race")
            return analysis
        except aiohttp.ClientError as exc:
            logger.error("Vote race test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}
        finally:
            await self.close()

    async def test_limit_bypass(self, target: str, endpoint: str) -> Dict[str, Any]:
        """Test rate limit bypass via race condition.

        Sends concurrent requests to overwhelm rate limiting before
        the counter can be incremented.

        Args:
            target: Base URL of the target application.
            endpoint: Rate-limited endpoint path.

        Returns:
            Dictionary with rate limit bypass test results.
        """
        url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
        logger.info("Testing rate limit bypass on %s", url)

        try:
            # First, determine the rate limit threshold
            rate_limit_found = False
            limit_threshold = 0
            session = await self._get_session()

            for i in range(1, 101):
                async with session.get(url) as resp:
                    if resp.status == 429:
                        rate_limit_found = True
                        limit_threshold = i
                        break

            if not rate_limit_found:
                limit_threshold = 100

            # Now race the rate limit
            race_results = await self._send_race_requests(
                url, "GET", concurrency=limit_threshold + 20
            )

            successful_bypass = sum(
                1 for r in race_results if r.get("status_code") == 200
            )
            rate_limited = sum(
                1 for r in race_results if r.get("status_code") == 429
            )

            analysis = {
                "url": url,
                "test_type": "rate_limit_bypass",
                "rate_limit_threshold": limit_threshold,
                "rate_limit_detected": rate_limit_found,
                "successful_bypass_count": successful_bypass,
                "rate_limited_count": rate_limited,
                "bypass_detected": successful_bypass > limit_threshold,
                "bypass_ratio": round(
                    successful_bypass / (successful_bypass + rate_limited), 2
                ) if (successful_bypass + rate_limited) > 0 else 0,
            }
            analysis = await self._ai_analyze(analysis, "rate_limit_bypass")
            return analysis
        except aiohttp.ClientError as exc:
            logger.error("Rate limit bypass test failed: %s", exc)
            return {"error": str(exc), "vulnerable": False}
        finally:
            await self.close()
