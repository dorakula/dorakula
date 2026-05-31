"""Failure Recovery System - Classifies errors and provides recovery actions."""

import asyncio
import logging
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


logger = logging.getLogger(__name__)


class ErrorType(Enum):
    """Classification of error types."""
    NETWORK = "network"
    AUTH = "authentication"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    TOOL_ERROR = "tool_error"
    PERMISSION = "permission"
    RESOURCE = "resource"
    VALIDATION = "validation"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


RECOVERY_STRATEGIES: Dict[ErrorType, Dict[str, Any]] = {
    ErrorType.NETWORK: {
        "action": "retry_with_backoff",
        "max_retries": 3,
        "base_delay": 2.0,
        "backoff_factor": 2.0,
        "suggestions": [
            "Check network connectivity",
            "Verify target host is reachable",
            "Try alternative DNS resolution",
            "Check for firewall/IPS blocking",
        ],
    },
    ErrorType.AUTH: {
        "action": "reauthenticate",
        "max_retries": 2,
        "base_delay": 1.0,
        "backoff_factor": 1.0,
        "suggestions": [
            "Verify credentials are valid",
            "Check for session expiration",
            "Try alternative authentication method",
            "Check for MFA/2FA requirements",
        ],
    },
    ErrorType.TIMEOUT: {
        "action": "increase_timeout_retry",
        "max_retries": 3,
        "base_delay": 5.0,
        "backoff_factor": 2.0,
        "suggestions": [
            "Increase request timeout",
            "Split large requests into smaller chunks",
            "Check target server response time",
            "Use asynchronous processing",
        ],
    },
    ErrorType.RATE_LIMIT: {
        "action": "respect_rate_limit",
        "max_retries": 5,
        "base_delay": 60.0,
        "backoff_factor": 1.5,
        "suggestions": [
            "Wait for rate limit to reset",
            "Reduce request frequency",
            "Use request throttling",
            "Distribute requests across multiple endpoints",
        ],
    },
    ErrorType.TOOL_ERROR: {
        "action": "fallback_alternative",
        "max_retries": 2,
        "base_delay": 1.0,
        "backoff_factor": 1.0,
        "suggestions": [
            "Try an alternative tool",
            "Check tool version compatibility",
            "Verify tool configuration",
            "Check for missing dependencies",
        ],
    },
    ErrorType.PERMISSION: {
        "action": "escalate_privileges",
        "max_retries": 1,
        "base_delay": 0.0,
        "backoff_factor": 1.0,
        "suggestions": [
            "Run with elevated privileges",
            "Check file/directory permissions",
            "Verify user/group membership",
            "Check SELinux/AppArmor restrictions",
        ],
    },
    ErrorType.RESOURCE: {
        "action": "free_resources_retry",
        "max_retries": 3,
        "base_delay": 10.0,
        "backoff_factor": 2.0,
        "suggestions": [
            "Free disk/memory resources",
            "Close unnecessary processes",
            "Increase resource limits",
            "Use streaming instead of buffering",
        ],
    },
    ErrorType.VALIDATION: {
        "action": "correct_input_retry",
        "max_retries": 2,
        "base_delay": 0.0,
        "backoff_factor": 1.0,
        "suggestions": [
            "Validate input parameters",
            "Check parameter types and ranges",
            "Review API documentation for correct format",
            "Sanitize special characters",
        ],
    },
    ErrorType.CONFIGURATION: {
        "action": "fix_config_retry",
        "max_retries": 1,
        "base_delay": 0.0,
        "backoff_factor": 1.0,
        "suggestions": [
            "Check configuration file syntax",
            "Verify required settings are present",
            "Reset to default configuration",
            "Check environment variables",
        ],
    },
    ErrorType.UNKNOWN: {
        "action": "generic_retry",
        "max_retries": 2,
        "base_delay": 5.0,
        "backoff_factor": 2.0,
        "suggestions": [
            "Review error message for details",
            "Check system logs",
            "Try restarting the operation",
            "Escalate to manual investigation",
        ],
    },
}


class FailureRecoverySystem:
    """Classifies errors and provides recovery strategies."""

    def __init__(self, ai_router: Any):
        self.ai_router = ai_router
        self.error_history: List[Dict[str, Any]] = []
        self.recovery_handlers: Dict[ErrorType, Optional[Callable]] = {
            et: None for et in ErrorType
        }

    def classify_error(self, error: Exception) -> ErrorType:
        """Classify an error into a specific ErrorType."""
        error_msg = str(error).lower()
        error_type_name = type(error).__name__.lower()

        # Network errors
        network_indicators = [
            "connectionrefused", "connection refused", "connectionreset",
            "connection reset", "broken pipe", "network unreachable",
            "no route to host", "name or service not known",
            "connectionerror", "connecttimeouterror",
        ]
        if any(ind in error_msg or ind in error_type_name for ind in network_indicators):
            return ErrorType.NETWORK

        # Timeout errors
        timeout_indicators = [
            "timeout", "timed out", "deadline exceeded",
            "readtimeout", "connecttimeout",
        ]
        if any(ind in error_msg or ind in error_type_name for ind in timeout_indicators):
            return ErrorType.TIMEOUT

        # Auth errors
        auth_indicators = [
            "unauthorized", "authentication failed", "invalid credentials",
            "access denied", "forbidden", "401", "403",
            "authenticationerror", "permissiondenied",
        ]
        if any(ind in error_msg or ind in error_type_name for ind in auth_indicators):
            return ErrorType.AUTH

        # Rate limit errors
        rate_indicators = [
            "rate limit", "too many requests", "429",
            "throttl", "quota exceeded", "slow down",
        ]
        if any(ind in error_msg for ind in rate_indicators):
            return ErrorType.RATE_LIMIT

        # Permission errors
        perm_indicators = [
            "permission denied", "eacces", "eperm",
            "not authorized", "insufficient privileges",
        ]
        if any(ind in error_msg for ind in perm_indicators):
            return ErrorType.PERMISSION

        # Resource errors
        resource_indicators = [
            "out of memory", "no space left", "disk full",
            "resource temporarily unavailable", "too many open files",
            "memoryerror", "oom",
        ]
        if any(ind in error_msg or ind in error_type_name for ind in resource_indicators):
            return ErrorType.RESOURCE

        # Validation errors
        validation_indicators = [
            "validation", "invalid input", "invalid parameter",
            "valueerror", "typeerror", "malformed",
        ]
        if any(ind in error_msg or ind in error_type_name for ind in validation_indicators):
            return ErrorType.VALIDATION

        # Configuration errors
        config_indicators = [
            "config", "configuration", "missing required",
            "keyerror", "environment variable",
        ]
        if any(ind in error_msg for ind in config_indicators):
            return ErrorType.CONFIGURATION

        # Tool errors
        tool_indicators = [
            "subprocess", "command failed", "tool error",
            "execution failed", "processerror",
        ]
        if any(ind in error_msg or ind in error_type_name for ind in tool_indicators):
            return ErrorType.TOOL_ERROR

        return ErrorType.UNKNOWN

    async def get_recovery_action(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Get a recovery action for a given error."""
        error_type = self.classify_error(error)
        strategy = RECOVERY_STRATEGIES.get(error_type, RECOVERY_STRATEGIES[ErrorType.UNKNOWN])

        error_record = {
            "error": str(error),
            "error_type": error_type.value,
            "error_class": type(error).__name__,
            "context": context or {},
            "strategy": strategy["action"],
            "timestamp": asyncio.get_event_loop().time(),
        }
        self.error_history.append(error_record)

        # Check for custom recovery handler
        custom_handler = self.recovery_handlers.get(error_type)
        if custom_handler:
            try:
                result = custom_handler(error, context)
                if asyncio.iscoroutine(result):
                    result = await result
                error_record["custom_recovery"] = result
                return {
                    "error_type": error_type.value,
                    "action": strategy["action"],
                    "max_retries": strategy["max_retries"],
                    "delay": strategy["base_delay"],
                    "suggestions": strategy["suggestions"],
                    "custom_result": result,
                }
            except Exception as e:
                logger.warning(f"Custom recovery handler failed: {e}")

        # Use AI for enhanced recovery suggestions
        ai_suggestions = await self._get_ai_recovery_suggestions(error, error_type, context)

        return {
            "error_type": error_type.value,
            "action": strategy["action"],
            "max_retries": strategy["max_retries"],
            "delay": strategy["base_delay"],
            "backoff_factor": strategy["backoff_factor"],
            "suggestions": strategy["suggestions"],
            "ai_suggestions": ai_suggestions,
        }

    async def _get_ai_recovery_suggestions(
        self,
        error: Exception,
        error_type: ErrorType,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Get AI-powered recovery suggestions."""
        prompt = (
            f"Error encountered during security assessment:\n"
            f"Error Type: {error_type.value}\n"
            f"Error Message: {str(error)}\n"
            f"Context: {context or 'None'}\n\n"
            f"Suggest specific recovery actions for a penetration testing / bug bounty context. "
            f"Include alternative approaches and workarounds."
        )
        try:
            suggestions = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are a security operations expert. Provide actionable recovery steps."
            )
            return suggestions
        except Exception as e:
            logger.debug(f"AI recovery suggestions failed: {e}")
            return ""

    def register_handler(
        self, error_type: ErrorType, handler: Callable
    ) -> None:
        """Register a custom recovery handler for an error type."""
        self.recovery_handlers[error_type] = handler
        logger.info(f"Registered custom handler for {error_type.value}")

    def get_error_stats(self) -> Dict[str, Any]:
        """Get statistics about error history."""
        if not self.error_history:
            return {"total_errors": 0, "breakdown": {}}

        breakdown: Dict[str, int] = {}
        for record in self.error_history:
            et = record["error_type"]
            breakdown[et] = breakdown.get(et, 0) + 1

        return {
            "total_errors": len(self.error_history),
            "breakdown": breakdown,
            "most_common": max(breakdown, key=breakdown.get) if breakdown else None,
        }
