#!/usr/bin/env python3
"""Dorakula Semantic Vulnerability Chaining Engine
Graph-based attack path discovery with cumulative impact estimation.
Advanced vulnerability correlation and attack chain builder.
"""
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class VulnNode:
    def __init__(self, vuln_id: str, vuln_type: str, severity: str, details: Dict):
        self.id = vuln_id
        self.type = vuln_type
        self.severity = severity
        self.details = details
        self.edges: List["VulnEdge"] = []

class VulnEdge:
    def __init__(self, source: VulnNode, target: VulnNode, condition: str, probability: float):
        self.source = source
        self.target = target
        self.condition = condition
        self.probability = probability

class SemanticVulnChainer:
    """Graph-based vulnerability chaining with AI enhancement"""
    
    CHAINING_RULES = {
        "info_disclosure": ["ssrf", "lfi", "path_traversal"],
        "ssrf": ["rce", "cloud_metadata_access", "internal_network_access"],
        "sqli": ["rce", "auth_bypass", "data_exfiltration", "file_read"],
        "xss": ["session_hijacking", "csrf_bypass", "admin_compromise"],
        "lfi": ["rce_via_log_poisoning", "rce_via_session", "source_code_disclosure"],
        "auth_bypass": ["privilege_escalation", "account_takeover", "admin_access"],
        "file_upload": ["rce", "stored_xss", "path_traversal"],
        "ssrf": ["internal_scan", "cloud_metadata", "rce_via_internal"],
        "deserialization": ["rce", "privilege_escalation"],
        "xxe": ["ssrf", "file_read", "rce"],
    }
    
    SEVERITY_SCORES = {"critical": 0.95, "high": 0.75, "medium": 0.50, "low": 0.25, "info": 0.10}
    
    def __init__(self, ai_router=None):
        self.ai_router = ai_router
        self.nodes: Dict[str, VulnNode] = {}
        self.chains_found: List[Dict] = []
    
    def _build_graph(self, vulnerabilities: List[Dict]) -> None:
        """Build vulnerability graph from findings"""
        self.nodes.clear()
        for i, vuln in enumerate(vulnerabilities):
            node_id = vuln.get("id", f"vuln-{i}")
            node = VulnNode(
                vuln_id=node_id,
                vuln_type=vuln.get("type", "unknown").lower(),
                severity=vuln.get("severity", "medium").lower(),
                details=vuln
            )
            self.nodes[node_id] = node
        
        for source in self.nodes.values():
            targets = self.CHAINING_RULES.get(source.type, [])
            for target in self.nodes.values():
                if target.type in targets and target.id != source.id:
                    prob = self.SEVERITY_SCORES.get(source.severity, 0.5)
                    edge = VulnEdge(source, target, f"{source.type} -> {target.type}", prob)
                    source.edges.append(edge)
    
    def _find_chains_dfs(self, max_depth: int = 4) -> List[List[VulnNode]]:
        """DFS-based chain discovery"""
        all_chains = []
        for start_node in self.nodes.values():
            self._dfs(start_node, [start_node], all_chains, max_depth)
        return all_chains
    
    def _dfs(self, current: VulnNode, path: List[VulnNode], results: List, max_depth: int):
        if len(path) >= max_depth:
            results.append(path[:])
            return
        if not current.edges:
            results.append(path[:])
            return
        for edge in current.edges:
            if edge.target not in path:
                path.append(edge.target)
                self._dfs(edge.target, path, results, max_depth)
                path.pop()
    
    async def find_chains(self, vulnerabilities: List[Dict], max_depth: int = 4) -> Dict[str, Any]:
        """Find semantic attack chains from vulnerabilities"""
        if len(vulnerabilities) < 2:
            return {"success": True, "chains": [], "message": "Need at least 2 vulnerabilities for chaining"}
        
        self._build_graph(vulnerabilities)
        raw_chains = self._find_chains_dfs(max_depth)
        
        # Score and rank chains
        scored_chains = []
        for chain in raw_chains:
            chain_score = self._score_chain(chain)
            scored_chains.append({
                "chain": [{"id": n.id, "type": n.type, "severity": n.severity} for n in chain],
                "score": chain_score,
                "cumulative_impact": self._estimate_impact(chain),
                "mitre_mapping": self._map_mitre(chain)
            })
        
        scored_chains.sort(key=lambda x: x["score"], reverse=True)
        
        # AI enhancement if available
        ai_chains = []
        if self.ai_router:
            ai_chains = await self._ai_chain_enhancement(vulnerabilities, scored_chains[:5])
        
        all_chains = scored_chains[:10]
        if ai_chains:
            all_chains.extend(ai_chains)
        
        self.chains_found = all_chains
        return {
            "success": True,
            "total_chains": len(all_chains),
            "chains": all_chains,
            "analysis_source": "graph+ai" if ai_chains else "graph-only"
        }
    
    def _score_chain(self, chain: List[VulnNode]) -> float:
        """Score chain based on severity and length"""
        if not chain:
            return 0.0
        base = sum(self.SEVERITY_SCORES.get(n.severity, 0.3) for n in chain)
        length_bonus = min(len(chain) * 0.15, 0.6)
        return min(base / len(chain) + length_bonus, 1.0)
    
    def _estimate_impact(self, chain: List[VulnNode]) -> str:
        types = {n.type for n in chain}
        if "rce" in types:
            return "CRITICAL - Full system compromise possible"
        if "privilege_escalation" in types or "admin_access" in types:
            return "HIGH - Privilege escalation to admin"
        if "data_exfiltration" in types:
            return "HIGH - Data breach possible"
        if "auth_bypass" in types:
            return "MEDIUM - Authentication bypass"
        return "MEDIUM - Multi-vulnerability exploitation"
    
    def _map_mitre(self, chain: List[VulnNode]) -> List[str]:
        tactics = []
        type_tactic_map = {
            "sqli": "T1190", "xss": "T1190", "ssrf": "T1190",
            "rce": "T1059", "auth_bypass": "T1078",
            "privilege_escalation": "T1068", "lfi": "T1083",
            "data_exfiltration": "T1041"
        }
        for node in chain:
            technique = type_tactic_map.get(node.type)
            if technique and technique not in tactics:
                tactics.append(technique)
        return tactics
    
    async def _ai_chain_enhancement(self, vulns: List[Dict], top_chains: List[Dict]) -> List[Dict]:
        if not self.ai_router:
            return []
        try:
            result = await self.ai_router.chat([
                {"role": "system", "content": "You are an attack chain analyst. Discover additional chains."},
                {"role": "user", "content": f"Vulns: {json.dumps(vulns, indent=2)[:1000]}\nTop found chains: {json.dumps(top_chains, indent=2)[:1000]}\nFind additional chains as JSON array."}
            ])
            if result.get("success"):
                content = result.get("content", "")
                if "```" in content:
                    content = content.split("```")[1]
                chains = json.loads(content.strip().removeprefix("json"))
                return [{"chain": c, "source": "ai-enhanced", "provider": result.get("provider", "")} for c in (chains if isinstance(chains, list) else [])]
        except Exception as e:
            logger.warning("AI chain enhancement failed: %s", e)
        return []
