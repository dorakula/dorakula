#!/usr/bin/env python3
"""DORAKULA Intelligent Orchestrator — inspired by HexStrike AI.

Adaptasi IntelligentDecisionEngine + BugBountyWorkflowManager dari hexstrike-ai
(https://github.com/0x4m4/hexstrike-ai) dengan filosofi DORAKULA:

DIFFERENCES dari hexstrike:
  - DORAKULA: 199 tools (lebih banyak dari hexstrike 150+)
  - DORAKULA: sovereign tools (no API key dependency)
  - DORAKULA: auto_pilot_exploit v3 (Automated Exploitation)
  - DORAKULA: ponytail fix v2.3 (smart param builder)

ADAPTATIONS:
  - tool_effectiveness: ratings untuk DORAKULA tools (bukan hexstrike tools)
  - technology_signatures: detect tech stack via whatweb/header_check
  - attack_patterns: map vuln type → DORAKULA tools
  - workflow builder: phased recon → adaptive tool selection → vector exhaustion

INTEGRATION:
  - scan_target() calls IntelligentDecisionEngine.select_tools()
  - Tools dipilih berdasarkan tech_stack (adaptive, bukan generic list)
  - Worklog generated real-time (setiap phase, bukan hanya di akhir)
"""
import logging, json, time, re, os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class TargetType(Enum):
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    BINARY_FILE = "binary_file"
    MOBILE_APP = "mobile_app"
    UNKNOWN = "unknown"


@dataclass
class WorklogEntry:
    """Single worklog entry — real-time tracking."""
    timestamp: str
    phase: str
    action: str
    target: str = ""
    tool: str = ""
    result: str = ""
    severity: str = ""
    details: str = ""

    def to_markdown(self) -> str:
        line = f"- **[{self.timestamp}]** `{self.phase}` | {self.action}"
        if self.target:
            line += f" | target: `{self.target}`"
        if self.tool:
            line += f" | tool: `{self.tool}`"
        if self.severity:
            line += f" | **{self.severity}**"
        if self.result:
            line += f" | {self.result}"
        if self.details:
            line += f"\n  - details: {self.details[:200]}"
        return line


class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization engine.

    Inspired by hexstrike-ai IntelligentDecisionEngine, adapted for DORAKULA.
    """

    def __init__(self):
        self.tool_effectiveness = self._init_tool_effectiveness()
        self.technology_signatures = self._init_technology_signatures()
        self.attack_patterns = self._init_attack_patterns()

    def _init_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Tool effectiveness ratings per target type (0.0-1.0).

        Higher = more effective for that target type.
        Based on DORAKULA's 199 tools (not hexstrike's 150).
        """
        return {
            TargetType.WEB_APPLICATION.value: {
                # Pure Python (always available)
                "xss_scan": 0.93,
                "ssrf_test": 0.92,
                "lfi_test": 0.90,
                "cmd_injection_test": 0.91,
                "cmd_blind_test": 0.88,
                "open_redirect_test": 0.89,
                "cors_check": 0.85,
                "cookie_security_check": 0.82,
                "header_check": 0.87,
                "jwt_analyze": 0.90,
                "jwt_none_bypass": 0.88,
                "jwt_crack": 0.85,
                "api_fuzz_rest": 0.89,
                "api_test_bola": 0.92,
                "graphql_introspect": 0.88,
                "api_fuzz_graphql": 0.87,
                "rest_api_fuzz": 0.86,
                "content_type_fuzz": 0.80,
                # v3 WAF bypass
                "ssrf_test_v3": 0.95,
                "lfi_test_v3": 0.93,
                "xss_test_v3": 0.94,
                "cmdi_test_v3": 0.92,
                # CLI tools (need binary)
                "nuclei_scan": 0.97,
                "nikto_scan": 0.85,
                "sqlmap_scan": 0.95,
                "ffuf_dir": 0.90,
                "gobuster_dir": 0.88,
                "feroxbuster_dir": 0.87,
                "whatweb_scan": 0.85,
                "httpx_probe": 0.88,
                "wpscan_enum": 0.97,  # high for WordPress
                "dalfox_xss": 0.96,
                "commix_test": 0.89,
                "wafw00f_detect": 0.85,
            },
            TargetType.NETWORK_HOST.value: {
                "nmap_scan": 0.97,
                "nmap_stealth": 0.92,
                "nmap_udp": 0.88,
                "rustscan": 0.93,
                "masscan": 0.95,
                "autorecon": 0.96,
                "dnsrecon": 0.88,
                "dnsenum": 0.85,
                "fierce_scan": 0.82,
                "traceroute_tool": 0.75,
                "ping_sweep": 0.85,
                "netbios_scan": 0.80,
                "smb_enum": 0.87,
                "enum4linux_scan": 0.85,
                "sslscan_tool": 0.88,
                "sslyze_scan": 0.86,
                "testssl_scan": 0.89,
            },
            TargetType.API_ENDPOINT.value: {
                "api_fuzz_rest": 0.95,
                "api_test_bola": 0.97,
                "api_fuzz_graphql": 0.93,
                "graphql_introspect": 0.92,
                "arjun_params": 0.95,
                "paramspider_crawl": 0.90,
                "jwt_analyze": 0.93,
                "jwt_none_bypass": 0.90,
                "jwt_crack": 0.87,
                "header_check": 0.88,
                "content_type_fuzz": 0.85,
                "nuclei_scan": 0.90,
            },
            TargetType.CLOUD_SERVICE.value: {
                # Sovereign cloud auditor
                "cloud_audit": 0.95,
                "ssrf_cloud_metadata": 0.97,
                "ssrf_test_v3": 0.95,
                # CLI tools (need binary)
                "aws_prowler": 0.95,
                "aws_pacu": 0.88,
                "scout_suite": 0.92,
                "cloudmapper": 0.88,
                "trivy_scan": 0.93,
                "kube_hunter": 0.92,
                "kube_bench": 0.90,
                "docker_bench": 0.88,
                "checkov_scan": 0.91,
                "terrascan_scan": 0.89,
            },
            TargetType.BINARY_FILE.value: {
                "strings_extract": 0.85,
                "binwalk_extract": 0.88,
                "checksec_tool": 0.92,
                "ghidra_analyze": 0.95,
                "radare2_analyze": 0.92,
                "gdb_debug": 0.87,
                "pwntools_exploit": 0.90,
                "angr_analyze": 0.88,
                "ropgadget_find": 0.89,
                "ropper_find": 0.87,
                "objdump_analyze": 0.82,
                "readelf_analyze": 0.85,
                "upx_unpack": 0.80,
            },
            TargetType.MOBILE_APP.value: {
                "mobile_scan": 0.95,
                "strings_extract": 0.85,
                "binwalk_extract": 0.80,
            },
        }

    def _init_technology_signatures(self) -> Dict[str, List[str]]:
        """Technology signatures for tech stack detection.

        Key → list of signatures (case-insensitive substring match).
        """
        return {
            "nginx": ["nginx", "nginx/1", "nginx/2"],
            "apache": ["apache", "httpd", "apache/2"],
            "iis": ["microsoft-iis", "iis/"],
            "php": ["php", "php/7", "php/8", "x-powered-by: php"],
            "aspnet": ["asp.net", "x-aspnet", "x-powered-by: asp.net"],
            "nodejs": ["express", "node.js", "x-powered-by: express"],
            "python": ["python", "django", "flask", "fastapi", "gunicorn"],
            "java": ["tomcat", "jetty", "jboss", "spring", "x-powered-by: jsp"],
            "wordpress": ["wordpress", "wp-content", "wp-includes", "x-pingback"],
            "drupal": ["drupal", "x-generator: drupal"],
            "joomla": ["joomla", "x-powered-by: joomla"],
            "graphql": ["graphql", "apollo", "hasura", "graphql-voyager"],
            "react": ["react", "next.js", "__next"],
            "vue": ["vue", "nuxt", "__nuxt"],
            "angular": ["angular", "ng-"],
            "cloudflare": ["cloudflare", "cf-ray", "__cf_bm"],
            "aws": ["aws", "x-amzn", "amazonaws"],
            "gcp": ["gcp", "google cloud", "x-goog"],
            "azure": ["azure", "microsoft azure", "x-azure"],
            "docker": ["docker", "x-docker"],
            "kubernetes": ["kubernetes", "k8s", "x-kubernetes"],
        }

    def _init_attack_patterns(self) -> Dict[str, Dict]:
        """Attack patterns: vuln type → priority + tools + payloads.

        Higher priority = test first.
        """
        return {
            "rce": {
                "priority": 10,
                "tools": ["cmdi_test_v3", "cmd_injection_test", "cmd_blind_test"],
                "description": "Remote Code Execution",
            },
            "sqli": {
                "priority": 9,
                "tools": ["sqlmap_scan", "api_fuzz_rest"],
                "description": "SQL Injection",
            },
            "ssrf": {
                "priority": 8,
                "tools": ["ssrf_test_v3", "ssrf_test", "ssrf_cloud_metadata"],
                "description": "Server-Side Request Forgery",
            },
            "idor": {
                "priority": 8,
                "tools": ["api_test_bola", "api_fuzz_rest"],
                "description": "Insecure Direct Object Reference",
            },
            "xss": {
                "priority": 7,
                "tools": ["xss_test_v3", "xss_scan", "dalfox_xss"],
                "description": "Cross-Site Scripting",
            },
            "lfi": {
                "priority": 7,
                "tools": ["lfi_test_v3", "lfi_test", "lfi_wrapper_test"],
                "description": "Local File Inclusion",
            },
            "jwt_auth": {
                "priority": 7,
                "tools": ["jwt_analyze", "jwt_none_bypass", "jwt_crack"],
                "description": "JWT Authentication Bypass",
            },
            "graphql": {
                "priority": 6,
                "tools": ["graphql_introspect", "api_fuzz_graphql", "graphql_fuzz"],
                "description": "GraphQL Vulnerabilities",
            },
            "cors": {
                "priority": 5,
                "tools": ["cors_check", "header_check"],
                "description": "CORS Misconfiguration",
            },
            "open_redirect": {
                "priority": 5,
                "tools": ["open_redirect_test"],
                "description": "Open Redirect",
            },
            "cookie_security": {
                "priority": 4,
                "tools": ["cookie_security_check"],
                "description": "Cookie Security Issues",
            },
        }

    # ============================================================
    # Public methods
    # ============================================================

    def detect_target_type(self, target: str, tech_stack: List[str] = None) -> TargetType:
        """Detect target type based on URL pattern + tech stack."""
        target_lower = target.lower()
        tech_str = " ".join(tech_stack or []).lower()

        if "/api/" in target_lower or "/graphql" in target_lower:
            return TargetType.API_ENDPOINT
        if target_lower.endswith((".apk", ".ipa")):
            return TargetType.MOBILE_APP
        if any(ext in target_lower for ext in [".elf", ".bin", ".exe", ".so"]):
            return TargetType.BINARY_FILE
        if any(t in tech_str for t in ["aws", "gcp", "azure", "kubernetes", "docker"]):
            return TargetType.CLOUD_SERVICE
        if target.startswith(("http://", "https://")):
            return TargetType.WEB_APPLICATION
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            return TargetType.NETWORK_HOST
        return TargetType.WEB_APPLICATION

    def detect_technology(self, headers: Dict[str, str], body: str = "") -> List[str]:
        """Detect technology stack from HTTP headers + body."""
        detected = []
        combined = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        combined += " " + body[:2000].lower()

        for tech, signatures in self.technology_signatures.items():
            for sig in signatures:
                if sig.lower() in combined:
                    detected.append(tech)
                    break
        return detected

    def select_tools(self, target_type: TargetType, tech_stack: List[str] = None,
                     available_tools: List[str] = None,
                     max_tools: int = 15) -> List[Tuple[str, float]]:
        """Select optimal tools based on target type + tech stack.

        Returns: list of (tool_name, effectiveness_score) sorted by score desc.
        """
        # Get base effectiveness for target type
        base_ratings = self.tool_effectiveness.get(target_type.value, {})

        # Filter by available tools (if specified)
        if available_tools:
            base_ratings = {t: s for t, s in base_ratings.items() if t in available_tools}

        # Boost tools based on tech stack
        boosted = {}
        for tool, score in base_ratings.items():
            boost = 0.0
            tech_str = " ".join(tech_stack or []).lower()

            # WordPress → boost wpscan
            if "wordpress" in tech_str and tool == "wpscan_enum":
                boost += 0.1
            # GraphQL → boost graphql tools
            if "graphql" in tech_str and "graphql" in tool:
                boost += 0.1
            # Cloud → boost cloud tools
            if any(c in tech_str for c in ["aws", "gcp", "azure"]) and "cloud" in tool:
                boost += 0.1
            if "kubernetes" in tech_str and tool in ["kube_hunter", "kube_bench"]:
                boost += 0.1
            # SSL detected → boost SSL tools
            if "nginx" in tech_str and tool in ["sslscan_tool", "testssl_scan"]:
                boost += 0.05

            boosted[tool] = min(score + boost, 1.0)

        # Sort by score descending, return top max_tools
        sorted_tools = sorted(boosted.items(), key=lambda x: -x[1])
        return sorted_tools[:max_tools]

    def get_attack_priorities(self, tech_stack: List[str] = None) -> List[Tuple[str, int]]:
        """Get attack priorities based on tech stack.

        Returns: list of (vuln_type, priority) sorted by priority desc.
        """
        priorities = []
        tech_str = " ".join(tech_stack or []).lower()

        for vuln_type, pattern in self.attack_patterns.items():
            priority = pattern["priority"]
            # Boost based on tech stack
            if "graphql" in tech_str and vuln_type == "graphql":
                priority += 2
            if any(c in tech_str for c in ["aws", "gcp", "azure"]) and vuln_type == "ssrf":
                priority += 2
            if "php" in tech_str and vuln_type in ["lfi", "rce"]:
                priority += 1
            if "wordpress" in tech_str and vuln_type in ["sqli", "xss"]:
                priority += 1
            priorities.append((vuln_type, priority))

        return sorted(priorities, key=lambda x: -x[1])


class BugBountyWorkflowManager:
    """Specialized workflow manager for bug bounty hunting.

    Inspired by hexstrike-ai BugBountyWorkflowManager, adapted for DORAKULA.
    """

    def __init__(self):
        self.engine = IntelligentDecisionEngine()

    def create_reconnaissance_workflow(self, target: str) -> Dict[str, Any]:
        """Create comprehensive reconnaissance workflow for bug bounty.

        Returns phased workflow plan.
        """
        return {
            "target": target,
            "phases": [
                {
                    "name": "subdomain_discovery",
                    "description": "Comprehensive subdomain enumeration",
                    "tools": ["subfinder_enum", "amass_enum", "certificate_transparency"],
                    "expected_outputs": ["subdomains list"],
                    "estimated_time": 300,
                },
                {
                    "name": "http_service_discovery",
                    "description": "Identify live HTTP services + tech stack",
                    "tools": ["httpx_probe", "whatweb_scan", "header_check"],
                    "expected_outputs": ["live_hosts", "tech_stack"],
                    "estimated_time": 180,
                },
                {
                    "name": "endpoint_discovery",
                    "description": "Discover URLs + endpoints",
                    "tools": ["gau_urls", "waybackurls", "katana_crawl"],
                    "expected_outputs": ["endpoints list"],
                    "estimated_time": 240,
                },
                {
                    "name": "parameter_discovery",
                    "description": "Discover hidden parameters",
                    "tools": ["arjun_params", "paramspider_crawl"],
                    "expected_outputs": ["params list"],
                    "estimated_time": 120,
                },
            ],
            "total_estimated_time": 840,
        }

    def build_pinpoints_from_recon(self, target: str, recon: Dict) -> List[Dict]:
        """Build attack pinpoints from recon results.

        v2 enhancement: derive pinpoints from tech_stack + endpoints.
        """
        pinpoints = []
        seen = set()

        # Pinpoint from endpoints
        for endpoint in recon.get("endpoints", [])[:20]:
            if endpoint not in seen:
                pinpoints.append({
                    "url": endpoint,
                    "type": "endpoint",
                    "source": "recon",
                })
                seen.add(endpoint)

        # Pinpoint from tech_stack — derive attack targets
        tech_stack = recon.get("tech_stack", [])
        tech_str = " ".join(tech_stack).lower()

        if "wordpress" in tech_str:
            wp_paths = ["/wp-admin", "/wp-login.php", "/wp-content/uploads",
                       "/wp-json/wp/v2/users", "/xmlrpc.php"]
            for path in wp_paths:
                url = f"{target.rstrip('/')}{path}"
                if url not in seen:
                    pinpoints.append({"url": url, "type": "wordpress", "source": "tech_stack"})
                    seen.add(url)

        if "graphql" in tech_str:
            gql_paths = ["/graphql", "/api/graphql", "/graphiql"]
            for path in gql_paths:
                url = f"{target.rstrip('/')}{path}"
                if url not in seen:
                    pinpoints.append({"url": url, "type": "graphql", "source": "tech_stack"})
                    seen.add(url)

        if any(c in tech_str for c in ["aws", "gcp", "azure"]):
            pinpoints.append({
                "url": target,
                "type": "cloud_metadata",
                "source": "tech_stack",
                "note": "Test SSRF for cloud metadata access",
            })

        # Common paths (always include)
        common_paths = ["/api", "/admin", "/login", "/.env", "/.git/config",
                       "/swagger.json", "/openapi.json"]
        for path in common_paths:
            url = f"{target.rstrip('/')}{path}"
            if url not in seen:
                pinpoints.append({"url": url, "type": "common_path", "source": "common"})
                seen.add(url)

        return pinpoints

    def derive_vectors_from_findings(self, findings: List[Dict],
                                       existing_pinpoints: List[Dict]) -> List[Dict]:
        """Derive new attack vectors from findings.

        v3 enhancement: continuous chaining.
        Example: finding /admin → derive admin auth bypass + admin API fuzzing.
        """
        new_pinpoints = []
        seen_urls = {p.get("url") for p in existing_pinpoints}

        for finding in findings:
            pinpoint_url = finding.get("pinpoint_url", "")
            vector = finding.get("vector", "")
            severity = finding.get("severity", "")

            # If we found admin endpoint, derive admin-specific attacks
            if "/admin" in pinpoint_url and pinpoint_url not in seen_urls:
                new_pinpoints.append({
                    "url": pinpoint_url,
                    "type": "admin_exploit",
                    "source": "derived_from_finding",
                    "derived_from": vector,
                })
                seen_urls.add(pinpoint_url)

            # If SSRF found, derive cloud metadata test
            if "ssrf" in vector.lower() and severity in ("HIGH", "CRITICAL"):
                metadata_url = f"{pinpoint_url}?url=http://169.254.169.254/latest/meta-data/"
                if metadata_url not in seen_urls:
                    new_pinpoints.append({
                        "url": metadata_url,
                        "type": "ssrf_metadata_exploit",
                        "source": "derived_from_finding",
                        "derived_from": vector,
                    })
                    seen_urls.add(metadata_url)

            # If JWT found, derive token forgery test
            if "jwt" in vector.lower() and severity in ("HIGH", "CRITICAL"):
                new_pinpoints.append({
                    "url": pinpoint_url,
                    "type": "jwt_forge_exploit",
                    "source": "derived_from_finding",
                    "derived_from": vector,
                })

            # If LFI found, derive sensitive file read
            if "lfi" in vector.lower() and severity in ("HIGH", "CRITICAL"):
                for file_path in ["/etc/shadow", "/etc/hosts", "/proc/self/environ"]:
                    lfi_url = f"{pinpoint_url}?file=../../../../{file_path.lstrip('/')}"
                    if lfi_url not in seen_urls:
                        new_pinpoints.append({
                            "url": lfi_url,
                            "type": "lfi_sensitive_read",
                            "source": "derived_from_finding",
                            "derived_from": vector,
                        })
                        seen_urls.add(lfi_url)

        return new_pinpoints


class WorklogManager:
    """Real-time worklog generation — writes to file as scan progresses.

    Per user vision: worklog dibuat real-time, bukan hanya di akhir.
    Semua temuan (CRITICAL/HIGH/MEDIUM/LOW) harus masuk.
    """

    def __init__(self, target: str, worklog_dir: str = "/tmp/dorakula_worklogs"):
        self.target = target
        self.worklog_dir = worklog_dir
        os.makedirs(worklog_dir, exist_ok=True)
        safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:50]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.filepath = os.path.join(worklog_dir, f"worklog_{safe_target}_{timestamp}.md")
        self.entries: List[WorklogEntry] = []
        self.findings_by_severity = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []
        }
        self._init_file()

    def _init_file(self):
        """Initialize worklog file with header."""
        header = f"""# DORAKULA Worklog — {self.target}

**Started:** {datetime.now(timezone.utc).isoformat()}
**Target:** {self.target}
**Status:** IN_PROGRESS

---

## Real-time Log

"""
        with open(self.filepath, "w") as f:
            f.write(header)

    def add_entry(self, phase: str, action: str, target: str = "",
                  tool: str = "", result: str = "",
                  severity: str = "", details: str = ""):
        """Add worklog entry + append to file (real-time)."""
        entry = WorklogEntry(
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S"),
            phase=phase, action=action, target=target, tool=tool,
            result=result, severity=severity, details=details,
        )
        self.entries.append(entry)

        # Append to file immediately (real-time)
        with open(self.filepath, "a") as f:
            f.write(entry.to_markdown() + "\n")

        # Track findings by severity
        if severity and severity in self.findings_by_severity:
            self.findings_by_severity[severity].append({
                "phase": phase, "tool": tool, "target": target,
                "result": result, "details": details,
            })

    def add_finding(self, finding: Dict):
        """Add vulnerability finding to worklog."""
        severity = finding.get("severity", "INFO")
        self.add_entry(
            phase="FINDING",
            action=f"Vulnerability detected: {finding.get('vector_label', finding.get('vector', 'unknown'))}",
            target=finding.get("pinpoint_url", ""),
            tool=finding.get("vector", ""),
            severity=severity,
            result=f"evidence: {finding.get('evidence', '')[:100]}",
            details=finding.get("poc_curl", ""),
        )

    def finalize(self, summary: Dict):
        """Finalize worklog with summary + findings by severity."""
        with open(self.filepath, "a") as f:
            f.write(f"\n---\n\n## Scan Summary\n\n")
            f.write(f"**Completed:** {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"**Status:** COMPLETE\n\n")
            f.write(f"### Findings by Severity\n\n")
            f.write(f"| Severity | Count |\n|----------|-------|\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                f.write(f"| {sev} | {len(self.findings_by_severity[sev])} |\n")
            f.write(f"\n### Detailed Findings\n\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                findings = self.findings_by_severity[sev]
                if findings:
                    f.write(f"#### {sev} ({len(findings)})\n\n")
                    for i, finding in enumerate(findings, 1):
                        f.write(f"{i}. **{finding['tool']}** on `{finding['target']}`\n")
                        f.write(f"   - {finding['result']}\n")
                        if finding.get("details"):
                            f.write(f"   - PoC: `{finding['details'][:150]}`\n")
                    f.write("\n")

            f.write(f"\n---\n*Generated by DORAKULA Intelligent Orchestrator*\n")

        return self.filepath
