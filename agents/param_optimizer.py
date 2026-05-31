"""Parameter Optimizer - AI-driven tool parameter optimization."""

import asyncio
import logging
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


# Known good defaults for common security tools
TOOL_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "fast_scan": "-sV -sC --top-ports 100 -T4",
        "full_scan": "-sV -sC -p- -T4",
        "stealth_scan": "-sS -sV -T2 --data-length 24 -D RND:5",
        "udp_scan": "-sU --top-ports 50 -T4",
        "vuln_scan": "-sV --script=vuln -T4",
        "default_params": {
            "timing": "T4",
            "version_detection": True,
            "default_scripts": True,
        },
    },
    "sqlmap": {
        "default_params": {
            "level": 3,
            "risk": 2,
            "batch": True,
            "random_agent": True,
        },
    },
    "ffuf": {
        "default_params": {
            "rate": 100,
            "threads": 40,
            "recursion_depth": 2,
            "auto_calibration": True,
        },
    },
    "nuclei": {
        "default_params": {
            "severity": "critical,high,medium",
            "rate_limit": 100,
            "bulk_size": 25,
            "timeout": 10,
        },
    },
    "feroxbuster": {
        "default_params": {
            "threads": 50,
            "timeout": 10,
            "depth": 4,
            "rate_limit": 100,
        },
    },
}


class ParameterOptimizer:
    """Optimizes tool parameters using AI analysis and known defaults."""

    def __init__(self, ai_router: Any):
        self.ai_router = ai_router
        self.optimization_history: List[Dict[str, Any]] = []

    async def optimize(
        self,
        tool_name: str,
        current_params: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Optimize parameters for a given tool based on context."""
        logger.info(f"Optimizing parameters for {tool_name}")

        tool_defaults = TOOL_DEFAULTS.get(tool_name, {})
        default_params = tool_defaults.get("default_params", {})

        prompt = (
            f"Optimize the following tool parameters for a security assessment:\n\n"
            f"Tool: {tool_name}\n"
            f"Current Parameters: {current_params}\n"
            f"Known Good Defaults: {default_params}\n\n"
            f"Context:\n"
            f"- Target: {context.get('target', 'unknown')}\n"
            f"- Assessment type: {context.get('assessment_type', 'unknown')}\n"
            f"- Technologies detected: {context.get('technologies', [])}\n"
            f"- Rate limiting detected: {context.get('rate_limited', False)}\n"
            f"- Stealth required: {context.get('stealth_required', False)}\n"
            f"- Time constraint: {context.get('time_constraint', 'normal')}\n"
            f"- Network speed: {context.get('network_speed', 'normal')}\n\n"
            f"Provide optimized parameters as a JSON-like structure with:\n"
            f"1. The optimized parameter values\n"
            f"2. A brief explanation for each change\n"
            f"3. Any additional flags or options to add\n"
            f"4. Any parameters to remove\n"
            f"Focus on effectiveness while respecting rate limits and stealth requirements."
        )

        try:
            optimization = await self.ai_router.query(
                prompt=prompt,
                system_prompt=(
                    "You are a security tool configuration expert. "
                    "Provide optimized tool parameters as structured key-value pairs. "
                    "Always consider the operational context and constraints."
                )
            )

            result = {
                "tool": tool_name,
                "original_params": current_params,
                "defaults": default_params,
                "optimization_advice": optimization,
                "context": context,
            }

            self.optimization_history.append(result)
            logger.info(f"Parameter optimization complete for {tool_name}")
            return result

        except Exception as e:
            logger.error(f"Parameter optimization failed for {tool_name}: {e}")
            return {
                "tool": tool_name,
                "original_params": current_params,
                "defaults": default_params,
                "optimization_advice": f"Using defaults - AI optimization failed: {e}",
                "context": context,
                "error": str(e),
            }

    def get_quick_params(self, tool_name: str, scenario: str = "default") -> Dict[str, Any]:
        """Get quick parameter suggestions without AI call."""
        tool_info = TOOL_DEFAULTS.get(tool_name, {})
        if scenario in tool_info and scenario != "default_params":
            return {"params": tool_info[scenario]}
        return {"params": tool_info.get("default_params", {})}
