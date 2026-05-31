"""Graceful Degradation - Provides tool alternatives when failures occur."""

import asyncio
import logging
from typing import Any, Callable, Coroutine, Dict, List, Optional


logger = logging.getLogger(__name__)


TOOL_ALTERNATIVES: Dict[str, List[Dict[str, Any]]] = {
    "nmap": [
        {"tool": "masscan", "reason": "Faster port scanning for large ranges", "tradeoff": "Less service detection accuracy"},
        {"tool": "rustscan", "reason": "Rust-based fast port scanner", "tradeoff": "Requires separate service enumeration"},
        {"tool": "unicornscan", "reason": "Async port scanner", "tradeoff": "Different output format"},
    ],
    "sqlmap": [
        {"tool": "bbqsql", "reason": "Blind SQL injection tool", "tradeoff": "Limited to blind injection"},
        {"tool": "nosqlmap", "reason": "NoSQL injection tool", "tradeoff": "NoSQL databases only"},
        {"tool": "ghauri", "reason": "Advanced SQL injection detection", "tradeoff": "Newer tool, less tested"},
    ],
    "ffuf": [
        {"tool": "feroxbuster", "reason": "Rust-based directory fuzzer with recursion", "tradeoff": "Different filter syntax"},
        {"tool": "gobuster", "reason": "Go-based directory/DNS fuzzer", "tradeoff": "Fewer features"},
        {"tool": "dirsearch", "reason": "Python-based directory scanner", "tradeoff": "Slower than ffuf"},
    ],
    "nuclei": [
        {"tool": "nikto", "reason": "Web server vulnerability scanner", "tradeoff": "Fewer templates, more false positives"},
        {"tool": "wpscan", "reason": "WordPress-specific scanner", "tradeoff": "WordPress only"},
        {"tool": "testssl", "reason": "SSL/TLS vulnerability scanner", "tradeoff": "SSL only"},
    ],
    "burpsuite": [
        {"tool": "zap", "reason": "Open source web proxy", "tradeoff": "Less polished UI, fewer extensions"},
        {"tool": "caido", "reason": "Modern web proxy", "tradeoff": "Newer, smaller community"},
        {"tool": "mitmproxy", "reason": "CLI-based intercepting proxy", "tradeoff": "No GUI, steep learning curve"},
    ],
    "metasploit": [
        {"tool": "exploitdb", "reason": "Exploit database and searchsploit", "tradeoff": "No payload generation or handler"},
        {"tool": "pwntools", "reason": "CTF/exploit development framework", "tradeoff": "Requires more manual setup"},
        {"tool": "empire", "reason": "Post-exploitation framework", "tradeoff": "Different focus than Metasploit"},
    ],
    "hydra": [
        {"tool": "medusa", "reason": "Parallel login brute forcer", "tradeoff": "Fewer protocols supported"},
        {"tool": "ncrack", "reason": "Network authentication cracking", "tradeoff": "Less flexible"},
        {"tool": "patator", "reason": "Multi-purpose brute forcer", "tradeoff": "Slower, Python-based"},
    ],
    "dirb": [
        {"tool": "ffuf", "reason": "Faster directory fuzzer", "tradeoff": "Different wordlist format"},
        {"tool": "feroxbuster", "reason": "Recursive directory discovery", "tradeoff": "More resource intensive"},
        {"tool": "dirsearch", "reason": "Python-based directory brute force", "tradeoff": "Slower than ffuf"},
    ],
    "subfinder": [
        {"tool": "amass", "reason": "Comprehensive subdomain enumeration", "tradeoff": "Slower, more resource intensive"},
        {"tool": "assetfinder", "reason": "Simple subdomain finder", "tradeoff": "Fewer sources"},
        {"tool": "findomain", "reason": "Fast subdomain discovery", "tradeoff": "Less comprehensive"},
    ],
    "gobuster": [
        {"tool": "ffuf", "reason": "Faster fuzzer with more features", "tradeoff": "More complex syntax"},
        {"tool": "feroxbuster", "reason": "Auto-recursion and smart filtering", "tradeoff": "Higher memory usage"},
        {"tool": "dirsearch", "reason": "Python directory scanner", "tradeoff": "Slower than Go-based tools"},
    ],
}

DEGRADATION_LEVELS = {
    "full": "All tools available, no restrictions",
    "reduced": "Primary tool failed, using alternatives",
    "minimal": "Multiple failures, using basic alternatives",
    "manual": "All automated tools failed, manual approach required",
}


class GracefulDegradation:
    """Provides graceful degradation with tool alternatives."""

    def __init__(self, ai_router: Any):
        self.ai_router = ai_router
        self.failure_count: Dict[str, int] = {}
        self.degradation_level: str = "full"
        self.custom_alternatives: Dict[str, List[Dict[str, Any]]] = {}
        self.failure_log: List[Dict[str, Any]] = []

    def get_alternative(
        self,
        tool_name: str,
        failure_reason: str = "",
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Get an alternative tool or approach when the primary tool fails."""
        self.failure_count[tool_name] = self.failure_count.get(tool_name, 0) + 1
        self.failure_log.append({
            "tool": tool_name,
            "reason": failure_reason,
            "context": context or {},
            "count": self.failure_count[tool_name],
        })

        logger.info(f"Finding alternative for {tool_name} (failure: {failure_reason})")

        # Check custom alternatives first
        alternatives = self.custom_alternatives.get(tool_name, [])

        # Then check built-in alternatives
        if not alternatives:
            alternatives = TOOL_ALTERNATIVES.get(tool_name, [])

        if not alternatives:
            return self._no_alternative_available(tool_name, failure_reason)

        # Update degradation level
        self._update_degradation_level()

        # Select best alternative based on failure count and context
        selected = self._select_best_alternative(tool_name, alternatives, context)

        result = {
            "original_tool": tool_name,
            "failure_reason": failure_reason,
            "alternative": selected,
            "degradation_level": self.degradation_level,
            "failure_count": self.failure_count[tool_name],
            "all_alternatives": alternatives,
        }

        logger.info(
            f"Selected alternative for {tool_name}: {selected['tool']} "
            f"(degradation: {self.degradation_level})"
        )
        return result

    def _select_best_alternative(
        self,
        tool_name: str,
        alternatives: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Select the best alternative based on context and failure count."""
        if not alternatives:
            return {"tool": "manual", "reason": "No alternatives available", "tradeoff": "Manual analysis required"}

        failure_count = self.failure_count.get(tool_name, 0)
        if failure_count <= 1:
            return alternatives[0]
        elif failure_count <= 2 and len(alternatives) > 1:
            return alternatives[1]
        elif len(alternatives) > 2:
            return alternatives[2]
        return alternatives[-1]

    def _no_alternative_available(
        self, tool_name: str, failure_reason: str
    ) -> Dict[str, Any]:
        """Return result when no alternative is available."""
        self.degradation_level = "manual"
        return {
            "original_tool": tool_name,
            "failure_reason": failure_reason,
            "alternative": {
                "tool": "manual",
                "reason": "No automated alternative available",
                "tradeoff": "Requires manual analysis and intervention",
            },
            "degradation_level": "manual",
            "failure_count": self.failure_count.get(tool_name, 0),
            "all_alternatives": [],
        }

    def _update_degradation_level(self) -> None:
        """Update the overall degradation level based on failure counts."""
        total_failures = sum(self.failure_count.values())
        unique_failed = len(self.failure_count)

        if total_failures == 0:
            self.degradation_level = "full"
        elif total_failures <= 3 and unique_failed <= 1:
            self.degradation_level = "reduced"
        elif total_failures <= 8 and unique_failed <= 3:
            self.degradation_level = "minimal"
        else:
            self.degradation_level = "manual"

    def register_alternative(
        self, tool_name: str, alternative: Dict[str, Any]
    ) -> None:
        """Register a custom alternative for a tool."""
        if tool_name not in self.custom_alternatives:
            self.custom_alternatives[tool_name] = []
        self.custom_alternatives[tool_name].append(alternative)
        logger.info(f"Registered custom alternative for {tool_name}: {alternative.get('tool', 'unknown')}")

    async def get_ai_alternative(
        self,
        tool_name: str,
        failure_reason: str,
        task_description: str
    ) -> Dict[str, Any]:
        """Use AI to find an alternative approach when no built-in alternative exists."""
        prompt = (
            f"The tool '{tool_name}' failed with reason: {failure_reason}\n"
            f"Task: {task_description}\n\n"
            f"Suggest alternative approaches, tools, or techniques to accomplish the same task. "
            f"For each alternative, provide:\n"
            f"1. Tool or technique name\n"
            f"2. Why it works as an alternative\n"
            f"3. Tradeoffs compared to the original tool\n"
            f"4. Installation command (if applicable)\n"
            f"5. Example usage command"
        )
        try:
            ai_suggestion = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are a security tools expert. Suggest practical alternatives."
            )
            return {
                "original_tool": tool_name,
                "failure_reason": failure_reason,
                "alternative": {
                    "tool": "ai_suggested",
                    "reason": "AI-generated alternative",
                    "tradeoff": "May require adaptation",
                },
                "ai_suggestions": ai_suggestion,
                "degradation_level": self.degradation_level,
            }
        except Exception as e:
            logger.error(f"AI alternative suggestion failed: {e}")
            return self.get_alternative(tool_name, failure_reason)

    def get_status(self) -> Dict[str, Any]:
        """Get current degradation status."""
        return {
            "degradation_level": self.degradation_level,
            "level_description": DEGRADATION_LEVELS.get(self.degradation_level, "Unknown"),
            "failure_counts": dict(self.failure_count),
            "total_failures": sum(self.failure_count.values()),
            "unique_tools_failed": len(self.failure_count),
        }

    def reset(self) -> None:
        """Reset degradation state."""
        self.failure_count.clear()
        self.degradation_level = "full"
        self.failure_log.clear()
        logger.info("Graceful degradation state reset")
