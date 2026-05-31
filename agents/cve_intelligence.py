"""CVE Intelligence Manager with real NVD API integration."""

import asyncio
import aiohttp
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


class CVEIntelligenceManager:
    """Monitors and analyzes CVEs using NVD API and AI analysis."""

    def __init__(self, ai_router: Any, api_key: Optional[str] = None):
        self.ai_router = ai_router
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
        self.monitored_keywords: List[str] = []
        self.cve_cache: Dict[str, Dict[str, Any]] = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()

    async def monitor_cves(
        self,
        keywords: List[str],
        days: int = 7,
        max_results: int = 50
    ) -> List[Dict[str, Any]]:
        """Query NVD API for recent CVEs matching keywords."""
        self.monitored_keywords = keywords
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": max_results,
        }

        if self.api_key:
            params["apiKey"] = self.api_key

        all_cves: List[Dict[str, Any]] = []

        for keyword in keywords:
            params["keywordSearch"] = keyword
            try:
                cves = await self._fetch_nvd(params)
                all_cves.extend(cves)
                logger.info(f"Found {len(cves)} CVEs for keyword: {keyword}")
            except Exception as e:
                logger.error(f"NVD query failed for '{keyword}': {e}")

        deduplicated = {cve["id"]: cve for cve in all_cves}
        results = list(deduplicated.values())

        for cve in results:
            self.cve_cache[cve["id"]] = cve

        return results

    async def _fetch_nvd(self, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Fetch CVEs from the NVD API."""
        session = await self._get_session()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        async with session.get(NVD_API_BASE, params=params, headers=headers) as resp:
            if resp.status == 403:
                logger.warning("NVD API rate limited. Retrying after delay.")
                await asyncio.sleep(6)
                async with session.get(NVD_API_BASE, params=params, headers=headers) as retry_resp:
                    retry_resp.raise_for_status()
                    data = await retry_resp.json()
            elif resp.status == 200:
                data = await resp.json()
            else:
                resp.raise_for_status()
                data = {}

        vulnerabilities = data.get("vulnerabilities", [])
        parsed = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            metrics = cve.get("metrics", {})
            cvss_v3 = self._extract_cvss(metrics, "cvssMetricV31")
            if not cvss_v3:
                cvss_v3 = self._extract_cvss(metrics, "cvssMetricV30")
            cvss_v2 = self._extract_cvss(metrics, "cvssMetricV2")

            references = [
                ref.get("url", "") for ref in cve.get("references", [])
            ]

            parsed.append({
                "id": cve_id,
                "description": description,
                "cvss_v3": cvss_v3,
                "cvss_v2": cvss_v2,
                "references": references,
                "published": cve.get("published", ""),
                "lastModified": cve.get("lastModified", ""),
                "sourceIdentifier": cve.get("sourceIdentifier", ""),
                "weaknesses": self._extract_weaknesses(cve),
            })

        return parsed

    def _extract_cvss(self, metrics: Dict, key: str) -> Optional[Dict[str, Any]]:
        """Extract CVSS metrics from NVD response."""
        try:
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                return {
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                    "exploitability": metric_list[0].get("exploitabilityScore"),
                    "impact": metric_list[0].get("impactScore"),
                }
        except (IndexError, KeyError, TypeError) as e:
            logger.debug(f"CVSS extraction error for {key}: {e}")
        return None

    def _extract_weaknesses(self, cve: Dict) -> List[str]:
        """Extract CWE IDs from CVE data."""
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                weaknesses.append(desc.get("value", ""))
        return weaknesses

    async def _analyze_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AI analysis on a CVE."""
        prompt = (
            f"Analyze CVE: {cve_data['id']}\n"
            f"Description: {cve_data['description']}\n"
            f"CVSS v3 Score: {cve_data.get('cvss_v3', {}).get('score', 'N/A')}\n"
            f"CVSS v3 Vector: {cve_data.get('cvss_v3', {}).get('vector', 'N/A')}\n"
            f"Weaknesses: {', '.join(cve_data.get('weaknesses', []))}\n"
            f"References: {', '.join(cve_data.get('references', [])[:5])}\n\n"
            f"Provide:\n"
            f"1. Technical impact assessment\n"
            f"2. Attack complexity evaluation\n"
            f"3. Exploitation likelihood (high/medium/low)\n"
            f"4. Potential attack scenarios\n"
            f"5. Recommended detection methods\n"
            f"6. Suggested mitigation steps"
        )
        try:
            analysis = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are a senior vulnerability analyst. Provide thorough technical analysis."
            )
            return {
                "cve_id": cve_data["id"],
                "ai_analysis": analysis,
                "cvss_score": cve_data.get("cvss_v3", {}).get("score"),
            }
        except Exception as e:
            logger.error(f"CVE analysis failed for {cve_data['id']}: {e}")
            return {
                "cve_id": cve_data["id"],
                "ai_analysis": f"Analysis failed: {e}",
                "cvss_score": cve_data.get("cvss_v3", {}).get("score"),
            }

    async def search_exploit(self, cve_id: str) -> Dict[str, Any]:
        """Search for public exploits for a given CVE using NVD and AI analysis."""
        cve_data = self.cve_cache.get(cve_id)
        if not cve_data:
            params = {"cveId": cve_id}
            try:
                results = await self._fetch_nvd(params)
                if results:
                    cve_data = results[0]
                    self.cve_cache[cve_id] = cve_data
                else:
                    return {"cve_id": cve_id, "error": "CVE not found in NVD"}
            except Exception as e:
                return {"cve_id": cve_id, "error": f"NVD lookup failed: {e}"}

        analysis = await self._analyze_cve(cve_data)

        exploit_prompt = (
            f"Based on CVE {cve_id} with description:\n"
            f"{cve_data['description']}\n\n"
            f"CVSS: {cve_data.get('cvss_v3', {}).get('score', 'N/A')}\n"
            f"Identify:\n"
            f"1. Known public exploits (searchsploit, ExploitDB, GitHub)\n"
            f"2. Exploit reliability assessment\n"
            f"3. Required conditions for exploitation\n"
            f"4. Detection signatures (Snort/Suricata/YARA)\n"
            f"5. Patch availability and workarounds"
        )
        try:
            exploit_info = await self.ai_router.query(
                prompt=exploit_prompt,
                system_prompt="You are a threat intelligence analyst. Focus on actionable exploit information."
            )
            analysis["exploit_intelligence"] = exploit_info
        except Exception as e:
            logger.error(f"Exploit search AI call failed: {e}")
            analysis["exploit_intelligence"] = f"AI search failed: {e}"

        return analysis
