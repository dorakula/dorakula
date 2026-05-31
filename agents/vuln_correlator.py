"""Vulnerability Correlator - EXECUTOR Pattern
Graph-based chaining is PRIMARY (always works), AI analysis is OPTIONAL.
AI Agent = EXECUTOR only, runs tools, never creates tools. and MITRE ATT&CK mapping."""

import asyncio
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


logger = logging.getLogger(__name__)


MITRE_ATTACK_MAP: Dict[str, Dict[str, str]] = {
    "sql_injection": {
        "tactic": "Initial Access",
        "technique": "T1190 - Exploit Public-Facing Application",
        "subtechnique": "SQL Injection",
    },
    "xss": {
        "tactic": "Initial Access",
        "technique": "T1189 - Drive-by Compromise",
        "subtechnique": "Reflected/Stored XSS",
    },
    "ssrf": {
        "tactic": "Lateral Movement",
        "technique": "T1071 - Application Layer Protocol",
        "subtechnique": "SSRF to Internal Services",
    },
    "rce": {
        "tactic": "Execution",
        "technique": "T1203 - Exploitation for Client Execution",
        "subtechnique": "Remote Code Execution",
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique": "T1068 - Exploitation for Privilege Escalation",
        "subtechnique": "",
    },
    "lfi": {
        "tactic": "Execution",
        "technique": "T1059 - Command and Scripting Interpreter",
        "subtechnique": "LFI to RCE",
    },
    "rfi": {
        "tactic": "Execution",
        "technique": "T1059 - Command and Scripting Interpreter",
        "subtechnique": "RFI to RCE",
    },
    "xxe": {
        "tactic": "Credential Access",
        "technique": "T1005 - Data from Local System",
        "subtechnique": "XXE File Read",
    },
    "deserialization": {
        "tactic": "Execution",
        "technique": "T1203 - Exploitation for Client Execution",
        "subtechnique": "Insecure Deserialization",
    },
    "idor": {
        "tactic": "Credential Access",
        "technique": "T1078 - Valid Accounts",
        "subtechnique": "IDOR for Unauthorized Access",
    },
    "open_redirect": {
        "tactic": "Initial Access",
        "technique": "T1189 - Drive-by Compromise",
        "subtechnique": "Open Redirect Phishing",
    },
    "info_disclosure": {
        "tactic": "Discovery",
        "technique": "T1082 - System Information Discovery",
        "subtechnique": "Information Disclosure",
    },
}


CHAIN_RULES: Dict[str, List[Dict[str, Any]]] = {
    "sql_injection": [
        {"next": "rce", "condition": "SQLi with file write privileges or xp_cmdshell", "likelihood": "high"},
        {"next": "privilege_escalation", "condition": "DBA privileges obtained", "likelihood": "high"},
        {"next": "info_disclosure", "condition": "Database credentials extracted", "likelihood": "high"},
        {"next": "idor", "condition": "Data access beyond intended scope", "likelihood": "medium"},
    ],
    "xss": [
        {"next": "ssrf", "condition": "JavaScript fetch to internal endpoints", "likelihood": "medium"},
        {"next": "privilege_escalation", "condition": "Admin session hijacking via stored XSS", "likelihood": "high"},
        {"next": "open_redirect", "condition": "XSS used for phishing redirect", "likelihood": "medium"},
    ],
    "ssrf": [
        {"next": "rce", "condition": "SSRF to cloud metadata then code execution", "likelihood": "high"},
        {"next": "privilege_escalation", "condition": "SSRF to internal admin services", "likelihood": "medium"},
        {"next": "lfi", "condition": "SSRF to file:// protocol", "likelihood": "medium"},
        {"next": "info_disclosure", "condition": "SSRF to internal API data extraction", "likelihood": "high"},
    ],
    "lfi": [
        {"next": "rce", "condition": "LFI with log poisoning or PHP filter chains", "likelihood": "high"},
        {"next": "info_disclosure", "condition": "Sensitive file read (/etc/passwd, .env)", "likelihood": "high"},
    ],
    "xxe": [
        {"next": "ssrf", "condition": "XXE with out-of-band SSRF", "likelihood": "high"},
        {"next": "rce", "condition": "XXE with expect:// or PHP wrapper", "likelihood": "medium"},
        {"next": "info_disclosure", "condition": "XXE file read", "likelihood": "high"},
    ],
    "idor": [
        {"next": "privilege_escalation", "condition": "IDOR to admin resource access", "likelihood": "high"},
        {"next": "info_disclosure", "condition": "IDOR to PII/data exposure", "likelihood": "high"},
    ],
    "deserialization": [
        {"next": "rce", "condition": "Deserialization gadget chain to code execution", "likelihood": "high"},
        {"next": "privilege_escalation", "condition": "Deserialized object with elevated privileges", "likelihood": "medium"},
    ],
    "info_disclosure": [
        {"next": "sql_injection", "condition": "Leaked database credentials enable SQLi", "likelihood": "medium"},
        {"next": "privilege_escalation", "condition": "Leaked secrets/keys enable escalation", "likelihood": "high"},
        {"next": "ssrf", "condition": "Internal endpoints disclosed via info leak", "likelihood": "medium"},
    ],
}


class VulnerabilityCorrelator:
    """Correlates vulnerabilities to find attack chains using graph-based analysis."""

    def __init__(self, ai_router: Any):
        self.ai_router = ai_router
        self.vulnerability_graph: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.attack_chains: List[Dict[str, Any]] = []

    async def find_attack_chains(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find attack chains from a list of vulnerabilities using graph-based analysis."""
        if not vulnerabilities:
            logger.info("No vulnerabilities to correlate")
            return []

        self._build_graph(vulnerabilities)

        rule_chains = self._find_rule_based_chains(vulnerabilities)
        # AI chains are OPTIONAL - graph-based rules are PRIMARY
        ai_chains = []  # Skip AI chains to save RAM; use rule-based only

        all_chains = rule_chains + ai_chains

        for chain in all_chains:
            chain["cumulative_impact"] = self._calculate_cumulative_impact(chain)
            chain["mitre_mapping"] = self._map_to_mitre(chain)

        all_chains.sort(key=lambda c: c["cumulative_impact"]["score"], reverse=True)

        self.attack_chains = all_chains
        logger.info(f"Found {len(all_chains)} attack chains")
        return all_chains

    def _build_graph(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Build a directed graph of vulnerability relationships."""
        self.vulnerability_graph.clear()
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown").lower()
            vuln_id = vuln.get("id", id(vuln))
            self.vulnerability_graph[vuln_id] = []

            if vuln_type in CHAIN_RULES:
                for chain_rule in CHAIN_RULES[vuln_type]:
                    next_type = chain_rule["next"]
                    for other in vulnerabilities:
                        if other.get("type", "").lower() == next_type:
                            self.vulnerability_graph[vuln_id].append({
                                "target_id": other.get("id", id(other)),
                                "target_type": next_type,
                                "condition": chain_rule["condition"],
                                "likelihood": chain_rule["likelihood"],
                            })

    def _find_rule_based_chains(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find attack chains using predefined chaining rules."""
        chains: List[Dict[str, Any]] = []
        vuln_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_by_type[vuln.get("type", "unknown").lower()].append(vuln)

        visited: Set[str] = set()

        for start_type, start_vulns in vuln_by_type.items():
            if start_type not in CHAIN_RULES:
                continue

            for start_vuln in start_vulns:
                start_id = start_vuln.get("id", str(id(start_vuln)))
                if start_id in visited:
                    continue

                for chain_rule in CHAIN_RULES[start_type]:
                    next_type = chain_rule["next"]
                    if next_type in vuln_by_type:
                        for next_vuln in vuln_by_type[next_type]:
                            chain_key = f"{start_id}->{next_vuln.get('id', str(id(next_vuln)))}"
                            if chain_key not in visited:
                                visited.add(chain_key)
                                chains.append({
                                    "source": "rule_based",
                                    "steps": [start_vuln, next_vuln],
                                    "conditions": [chain_rule["condition"]],
                                    "likelihoods": [chain_rule["likelihood"]],
                                    "chain_type": f"{start_type} -> {next_type}",
                                })

            visited.add(start_id)

        # Multi-hop chains via DFS
        multi_hop = self._find_multi_hop_chains(vulnerabilities, vuln_by_type, max_depth=4)
        chains.extend(multi_hop)

        return chains

    def _find_multi_hop_chains(
        self,
        vulnerabilities: List[Dict[str, Any]],
        vuln_by_type: Dict[str, List[Dict[str, Any]]],
        max_depth: int = 4
    ) -> List[Dict[str, Any]]:
        """Find multi-hop attack chains via depth-first search."""
        chains: List[Dict[str, Any]] = []
        vuln_map = {v.get("id", str(id(v))): v for v in vulnerabilities}

        def dfs(
            current_type: str,
            path: List[Dict[str, Any]],
            conditions: List[str],
            likelihoods: List[str],
            visited_types: Set[str],
            depth: int
        ) -> None:
            if depth >= max_depth:
                return
            if current_type not in CHAIN_RULES:
                return

            for chain_rule in CHAIN_RULES[current_type]:
                next_type = chain_rule["next"]
                if next_type in visited_types:
                    continue

                if next_type in vuln_by_type:
                    for next_vuln in vuln_by_type[next_type]:
                        new_path = path + [next_vuln]
                        new_conditions = conditions + [chain_rule["condition"]]
                        new_likelihoods = likelihoods + [chain_rule["likelihood"]]
                        new_visited = visited_types | {next_type}

                        if len(new_path) >= 3:
                            chains.append({
                                "source": "rule_based_multi_hop",
                                "steps": new_path,
                                "conditions": new_conditions,
                                "likelihoods": new_likelihoods,
                                "chain_type": " -> ".join(
                                    v.get("type", "?") for v in new_path
                                ),
                            })

                        dfs(next_type, new_path, new_conditions, new_likelihoods, new_visited, depth + 1)

        for start_type in vuln_by_type:
            for start_vuln in vuln_by_type[start_type]:
                dfs(
                    start_type,
                    [start_vuln],
                    [],
                    [],
                    {start_type},
                    1,
                )

        return chains[:50]

    async def _find_ai_chains(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Use AI to discover non-obvious attack chains."""
        vuln_summary = "\n".join(
            f"- {v.get('type', 'unknown')} (severity: {v.get('severity', 'N/A')}, "
            f"endpoint: {v.get('endpoint', v.get('url', 'N/A'))}): "
            f"{v.get('description', 'No description')}"
            for v in vulnerabilities
        )

        prompt = (
            f"Analyze these vulnerabilities and identify attack chains:\n\n"
            f"{vuln_summary}\n\n"
            f"Find non-obvious combinations where one vulnerability enables or amplifies another. "
            f"For each chain, provide:\n"
            f"1. Chain sequence (ordered vulnerability types)\n"
            f"2. How each step enables the next\n"
            f"3. Overall impact assessment\n"
            f"4. Likelihood of successful chaining\n"
            f"5. Required conditions\n"
            f"Focus on realistic, exploitable chains, not theoretical possibilities."
        )

        try:
            ai_analysis = await self.ai_router.query(
                prompt=prompt,
                system_prompt=(
                    "You are an expert penetration tester specializing in vulnerability chaining. "
                    "Identify realistic attack paths that combine multiple vulnerabilities."
                )
            )
            return [{
                "source": "ai_analysis",
                "steps": vulnerabilities,
                "ai_analysis": ai_analysis,
                "chain_type": "ai_identified",
            }]
        except Exception as e:
            logger.error(f"AI chain analysis failed: {e}")
            return []

    def _calculate_cumulative_impact(self, chain: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate the cumulative impact score of an attack chain."""
        severity_scores = {"critical": 10.0, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}

        steps = chain.get("steps", [])
        if not steps:
            return {"score": 0.0, "level": "none", "description": "Empty chain"}

        total_score = 0.0
        for step in steps:
            severity = step.get("severity", "low").lower()
            total_score += severity_scores.get(severity, 3.0)

        chain_multiplier = 1.0 + (0.25 * max(0, len(steps) - 1))
        likelihoods = chain.get("likelihoods", [])
        if "high" in likelihoods:
            likelihood_mult = 1.2
        elif "medium" in likelihoods:
            likelihood_mult = 1.0
        else:
            likelihood_mult = 0.8

        final_score = min(10.0, (total_score / len(steps)) * chain_multiplier * likelihood_mult)

        if final_score >= 9.0:
            level = "critical"
        elif final_score >= 7.0:
            level = "high"
        elif final_score >= 4.0:
            level = "medium"
        else:
            level = "low"

        return {
            "score": round(final_score, 2),
            "level": level,
            "chain_length": len(steps),
            "multiplier_applied": chain_multiplier,
            "description": f"{len(steps)}-step chain with {level} cumulative impact (score: {final_score:.1f})",
        }

    def _map_to_mitre(self, chain: Dict[str, Any]) -> List[Dict[str, str]]:
        """Map attack chain steps to MITRE ATT&CK framework."""
        mappings: List[Dict[str, str]] = []
        for step in chain.get("steps", []):
            vuln_type = step.get("type", "").lower()
            if vuln_type in MITRE_ATTACK_MAP:
                mapping = MITRE_ATTACK_MAP[vuln_type].copy()
                mapping["vulnerability_type"] = vuln_type
                mappings.append(mapping)
            else:
                mappings.append({
                    "vulnerability_type": vuln_type,
                    "tactic": "Unknown",
                    "technique": "Unmapped",
                    "subtechnique": "",
                })
        return mappings
