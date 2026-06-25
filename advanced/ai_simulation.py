#!/usr/bin/env python3
"""Dorakula AI-vs-AI Simulation
Red Team vs Blue Team automated simulation.
Measures residual risk after remediation.
What NO competitor has.
"""
import json
import logging
import asyncio
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class AIVsAISimulation:
    """Automated red team / blue team simulation"""
    
    def __init__(self, ai_router=None):
        self.ai_router = ai_router
        self.iterations: List[Dict] = []
        self.residual_risk: float = 1.0
    
    async def run_simulation(self, target_info: Dict, vulnerabilities: List[Dict], max_iterations: int = 5) -> Dict[str, Any]:
        """Run AI-vs-AI red team/blue team simulation"""
        if not self.ai_router:
            return {"success": False, "error": "AI router required for simulation"}
        
        self.iterations = []
        self.residual_risk = 1.0
        current_vulns = vulnerabilities.copy()
        defenses = []
        
        for iteration in range(1, max_iterations + 1):
            # RED TEAM: Attack
            red_result = await self._red_team_attack(target_info, current_vulns, defenses)
            
            # BLUE TEAM: Defend
            blue_result = await self._blue_team_defend(target_info, red_result, defenses)
            
            # Update defenses
            if blue_result.get("new_defenses"):
                defenses.extend(blue_result["new_defenses"])
            
            # Calculate residual risk
            attack_success = red_result.get("attack_successful", True)
            self.residual_risk = self._calculate_residual_risk(iteration, attack_success)
            
            iteration_data = {
                "iteration": iteration,
                "red_team": red_result,
                "blue_team": blue_result,
                "residual_risk": round(self.residual_risk, 3),
                "total_defenses": len(defenses),
                "attack_successful": attack_success
            }
            self.iterations.append(iteration_data)
            
            if self.residual_risk < 0.1:
                break
        
        return {
            "success": True,
            "total_iterations": len(self.iterations),
            "iterations": self.iterations,
            "final_residual_risk": round(self.residual_risk, 3),
            "risk_level": self._risk_level(self.residual_risk),
            "total_defenses_implemented": len(defenses),
            "recommendations": self._generate_recommendations()
        }
    
    async def _red_team_attack(self, target: Dict, vulns: List[Dict], defenses: List) -> Dict:
        result = await self.ai_router.chat([
            {"role": "system", "content": "You are a red team attacker. Find ways to exploit the target given known vulnerabilities and current defenses."},
            {"role": "user", "content": f"Target: {json.dumps(target)[:500]}\nVulns: {json.dumps(vulns)[:500]}\nDefenses: {json.dumps(defenses)[:500]}\n\nAttempt attack. Return JSON: {{attack_successful: bool, technique: str, bypassed_defenses: [], details: str}}"}
        ])
        
        if result.get("success"):
            try:
                content = result.get("content", "")
                if "```" in content:
                    content = content.split("```")[1]
                return json.loads(content.strip().removeprefix("json"))
            except json.JSONDecodeError:
                return {"attack_successful": True, "technique": "unknown", "details": "Parse error"}
        return {"attack_successful": True, "technique": "ai_unavailable"}
    
    async def _blue_team_defend(self, target: Dict, attack: Dict, current_defenses: List) -> Dict:
        result = await self.ai_router.chat([
            {"role": "system", "content": "You are a blue team defender. Implement defenses against the attack."},
            {"role": "user", "content": f"Target: {json.dumps(target)[:300]}\nAttack: {json.dumps(attack)[:300]}\nCurrent defenses: {json.dumps(current_defenses)[:300]}\n\nPropose defenses. Return JSON: {{new_defenses: [{{name, description, effectiveness: 0-1}}], attack_mitigated: bool}}"}
        ])
        
        if result.get("success"):
            try:
                content = result.get("content", "")
                if "```" in content:
                    content = content.split("```")[1]
                return json.loads(content.strip().removeprefix("json"))
            except json.JSONDecodeError:
                return {"new_defenses": [], "attack_mitigated": False}
        return {"new_defenses": [], "attack_mitigated": False}
    
    def _calculate_residual_risk(self, iteration: int, attack_success: bool) -> float:
        if attack_success:
            decay = 0.85 ** iteration
        else:
            decay = 0.6 ** iteration
        return min(max(decay, 0.0), 1.0)
    
    def _risk_level(self, risk: float) -> str:
        if risk >= 0.7: return "CRITICAL"
        if risk >= 0.4: return "HIGH"
        if risk >= 0.2: return "MEDIUM"
        return "LOW"
    
    def _generate_recommendations(self) -> List[str]:
        recs = []
        if self.residual_risk >= 0.4:
            recs.append("Significant residual risk remains - additional hardening required")
        if any(i.get("attack_successful") for i in self.iterations[-2:]):
            recs.append("Recent attacks still succeeding - review defense implementation")
        if self.residual_risk < 0.2:
            recs.append("Good security posture - continue monitoring")
        return recs
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_simulations": len(self.iterations),
            "residual_risk": round(self.residual_risk, 3),
            "risk_level": self._risk_level(self.residual_risk)
        }

    # ============================================================
    # v2: MITRE ATT&CK mapping + kill chain tracking (Mythos 4.2)
    # ============================================================

    MITRE_ATTACK_MAP = {
        "recon": {"tactic": "TA0043 Reconnaissance", "techniques": ["T1595 Active Scanning", "T1592 Gather Victim Host Info", "T1589 Gather Victim Identity Info"]},
        "initial_access": {"tactic": "TA0001 Initial Access", "techniques": ["T1190 Exploit Public-Facing Application", "T1078 Valid Accounts", "T1133 External Remote Services"]},
        "execution": {"tactic": "TA0002 Execution", "techniques": ["T1059 Command and Scripting Interpreter", "T1106 Native API", "T1053 Scheduled Task/Job"]},
        "persistence": {"tactic": "TA0003 Persistence", "techniques": ["T1098 Account Manipulation", "T1543 Create or Modify System Process", "T1505 Server Software Component"]},
        "privilege_escalation": {"tactic": "TA0004 Privilege Escalation", "techniques": ["T1068 Exploitation for Privilege Escalation", "T1548 Abuse Elevation Control Mechanism"]},
        "defense_evasion": {"tactic": "TA0005 Defense Evasion", "techniques": ["T1027 Obfuscated Files or Information", "T1562 Impair Defenses", "T1070 Indicator Removal"]},
        "credential_access": {"tactic": "TA0006 Credential Access", "techniques": ["T1110 Brute Force", "T1552 Unsecured Credentials", "T1056 Input Capture"]},
        "discovery": {"tactic": "TA0007 Discovery", "techniques": ["T1046 Network Service Discovery", "T1087 Account Discovery", "T1082 System Information Discovery"]},
        "lateral_movement": {"tactic": "TA0008 Lateral Movement", "techniques": ["T1021 Remote Services", "T1072 Software Deployment Tools", "T1550 Use Alternate Authentication Material"]},
        "collection": {"tactic": "TA0009 Collection", "techniques": ["T1005 Data from Local System", "T1039 Data from Network Shared Drive", "T1056 Input Capture"]},
        "exfiltration": {"tactic": "TA0010 Exfiltration", "techniques": ["T1041 Exfiltration Over C2 Channel", "T1567 Exfiltration Over Web Service", "T1048 Exfiltration Over Alternative Protocol"]},
        "impact": {"tactic": "TA0040 Impact", "techniques": ["T1485 Data Destruction", "T1489 Service Stop", "T1490 Inhibit System Recovery"]},
    }

    def map_to_mitre(self, attack_result: Dict[str, Any]) -> Dict[str, Any]:
        """Map simulation attack result to MITRE ATT&CK framework (Mythos 4.2)."""
        technique = attack_result.get("technique", "").lower()
        details = attack_result.get("details", "").lower()

        # Determine which kill chain phase this attack belongs to
        phase = "initial_access"  # default
        if any(k in technique or k in details for k in ["scan", "recon", "enumerate"]):
            phase = "recon"
        elif any(k in technique or k in details for k in ["exploit", "inject", "rce", "execute"]):
            phase = "initial_access"
        elif any(k in technique or k in details for k in ["persist", "backdoor", "cron"]):
            phase = "persistence"
        elif any(k in technique or k in details for k in ["escalat", "privilege", "sudo"]):
            phase = "privilege_escalation"
        elif any(k in technique or k in details for k in ["evade", "obfusc", "hide"]):
            phase = "defense_evasion"
        elif any(k in technique or k in details for k in ["credential", "password", "token"]):
            phase = "credential_access"
        elif any(k in technique or k in details for k in ["discover", "scan", "map"]):
            phase = "discovery"
        elif any(k in technique or k in details for k in ["lateral", "pivot", "remote"]):
            phase = "lateral_movement"
        elif any(k in technique or k in details for k in ["collect", "gather", "harvest"]):
            phase = "collection"
        elif any(k in technique or k in details for k in ["exfil", "download", "transfer"]):
            phase = "exfiltration"
        elif any(k in technique or k in details for k in ["destroy", "encrypt", "ransom"]):
            phase = "impact"

        mitre_info = self.MITRE_ATTACK_MAP.get(phase, {})
        return {
            "kill_chain_phase": phase,
            "mitre_tactic": mitre_info.get("tactic", "Unknown"),
            "mitre_techniques": mitre_info.get("techniques", []),
            "attack_technique": technique,
            "attack_successful": attack_result.get("attack_successful", False),
        }

    def get_kill_chain_summary(self) -> Dict[str, Any]:
        """Generate kill chain summary from all simulation iterations."""
        if not self.iterations:
            return {"error": "No simulation iterations to summarize"}

        kill_chain = {}
        for iteration in self.iterations:
            red_result = iteration.get("red_team", {})
            mitre_mapping = self.map_to_mitre(red_result)
            phase = mitre_mapping["kill_chain_phase"]

            if phase not in kill_chain:
                kill_chain[phase] = {
                    "tactic": mitre_mapping["mitre_tactic"],
                    "techniques_tested": [],
                    "successful_attacks": 0,
                    "failed_attacks": 0,
                }

            kill_chain[phase]["techniques_tested"].extend(mitre_mapping["mitre_techniques"])
            if mitre_mapping["attack_successful"]:
                kill_chain[phase]["successful_attacks"] += 1
            else:
                kill_chain[phase]["failed_attacks"] += 1

        # Deduplicate techniques
        for phase_data in kill_chain.values():
            phase_data["techniques_tested"] = list(set(phase_data["techniques_tested"]))

        return {
            "check": "kill_chain_summary",
            "version": "v2-2025",
            "kill_chain": kill_chain,
            "phases_covered": len(kill_chain),
            "total_successful_attacks": sum(p["successful_attacks"] for p in kill_chain.values()),
            "total_failed_attacks": sum(p["failed_attacks"] for p in kill_chain.values()),
            "residual_risk": round(self.residual_risk, 3),
            "risk_level": self._risk_level(self.residual_risk),
            "mythos_reference": "4.2: MITRE ATT&CK Alignment",
        }
