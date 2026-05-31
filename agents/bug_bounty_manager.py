"""Bug Bounty Workflow Manager with AI-assisted strategy planning."""

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class BugBountyPhase(Enum):
    """Phases of a bug bounty engagement."""
    RECON = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


@dataclass
class BugBountyTarget:
    """Represents a bug bounty target."""
    scope: List[str]
    url: str
    description: str = ""
    out_of_scope: List[str] = field(default_factory=list)
    notes: str = ""
    technologies: List[str] = field(default_factory=list)
    phase: BugBountyPhase = BugBountyPhase.RECON
    findings: List[Dict[str, Any]] = field(default_factory=list)


class BugBountyWorkflowManager:
    """Manages bug bounty engagement workflow with AI-assisted planning."""

    def __init__(self, ai_router: Any):
        self.ai_router = ai_router
        self.engagements: Dict[str, BugBountyTarget] = {}

    async def start_engagement(
        self,
        target_url: str,
        scope: List[str],
        out_of_scope: Optional[List[str]] = None,
        description: str = ""
    ) -> BugBountyTarget:
        """Start a new bug bounty engagement."""
        target = BugBountyTarget(
            scope=scope,
            url=target_url,
            description=description,
            out_of_scope=out_of_scope or []
        )
        self.engagements[target_url] = target
        logger.info(f"Started engagement for {target_url}")

        strategy = await self._plan_strategy(target, BugBountyPhase.RECON)
        target.notes = strategy
        return target

    async def _plan_strategy(
        self,
        target: BugBountyTarget,
        phase: BugBountyPhase
    ) -> str:
        """Use AI to plan strategy for a given phase."""
        prompt = (
            f"Plan a detailed bug bounty strategy for phase '{phase.value}' "
            f"on target: {target.url}\n"
            f"Scope: {', '.join(target.scope)}\n"
            f"Out of scope: {', '.join(target.out_of_scope)}\n"
            f"Technologies detected: {', '.join(target.technologies) or 'unknown'}\n"
            f"Previous findings: {len(target.findings)}\n"
            f"Provide specific tools, techniques, and test cases for this phase. "
            f"Prioritize based on common vulnerability patterns for the detected tech stack."
        )
        try:
            strategy = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are an expert bug bounty hunter and security researcher."
            )
            logger.info(f"AI strategy planned for {phase.value} on {target.url}")
            return strategy
        except Exception as e:
            logger.warning(f"AI strategy planning failed: {e}")
            return self._default_strategy(phase)

    def _default_strategy(self, phase: BugBountyPhase) -> str:
        """Provide a default strategy when AI is unavailable."""
        strategies = {
            BugBountyPhase.RECON:
                "1. DNS enumeration (subfinder, amass)\n"
                "2. Port scanning (nmap -sV -sC)\n"
                "3. Web technology detection (whatweb, wappalyzer)\n"
                "4. Directory fuzzing (feroxbuster, ffuf)\n"
                "5. SSL/TLS analysis (sslyze, testssl.sh)",

            BugBountyPhase.ENUMERATION:
                "1. Endpoint discovery (ffuf, feroxbuster with extensions)\n"
                "2. Parameter fuzzing (arjun, paramspider)\n"
                "3. API endpoint enumeration\n"
                "4. Backup file detection\n"
                "5. Source code analysis for hidden paths",

            BugBountyPhase.VULNERABILITY_SCAN:
                "1. Automated scanning (nuclei templates)\n"
                "2. XSS testing (dalfox, xsser)\n"
                "3. SQL injection (sqlmap)\n"
                "4. SSRF testing\n"
                "5. Authentication testing\n"
                "6. Business logic analysis",

            BugBountyPhase.EXPLOITATION:
                "1. Validate each finding with proof-of-concept\n"
                "2. Document reproduction steps\n"
                "3. Assess impact severity\n"
                "4. Check for chaining opportunities\n"
                "5. Verify scope boundaries",

            BugBountyPhase.POST_EXPLOITATION:
                "1. Determine data exposure\n"
                "2. Assess lateral movement potential\n"
                "3. Document full attack chain\n"
                "4. Verify persistence mechanisms\n"
                "5. Check for privilege escalation",

            BugBountyPhase.REPORTING:
                "1. Write clear vulnerability descriptions\n"
                "2. Include step-by-step reproduction\n"
                "3. Provide proof-of-concept code\n"
                "4. Assess CVSS scores\n"
                "5. Recommend remediations"
        }
        return strategies.get(phase, "No default strategy available.")

    async def execute_phase(
        self,
        target_url: str,
        phase: Optional[BugBountyPhase] = None
    ) -> Dict[str, Any]:
        """Execute a specific phase or advance to the next phase."""
        target = self.engagements.get(target_url)
        if not target:
            raise ValueError(f"No engagement found for {target_url}")

        current_phase = phase or target.phase
        strategy = await self._plan_strategy(target, current_phase)

        result = {
            "target": target_url,
            "phase": current_phase.value,
            "strategy": strategy,
            "previous_findings_count": len(target.findings),
            "recommendations": []
        }

        ai_prompt = (
            f"Based on the strategy for {current_phase.value} phase on {target_url}, "
            f"provide actionable next steps and specific commands/tools to run. "
            f"Consider the {len(target.findings)} findings so far."
        )
        try:
            recommendations = await self.ai_router.query(
                prompt=ai_prompt,
                system_prompt="You are a bug bounty strategist. Provide specific, actionable commands."
            )
            result["recommendations"] = recommendations
        except Exception as e:
            logger.warning(f"Failed to get AI recommendations: {e}")
            result["recommendations"] = "Follow the default strategy steps."

        if not phase:
            phase_order = list(BugBountyPhase)
            idx = phase_order.index(target.phase)
            if idx < len(phase_order) - 1:
                target.phase = phase_order[idx + 1]
                logger.info(f"Advanced to phase: {target.phase.value}")

        return result
