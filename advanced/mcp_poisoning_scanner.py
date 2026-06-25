#!/usr/bin/env python3
"""DORAKULA MCP Tool Poisoning Scanner — P0 #1 from audit.

Detects Tool Poisoning Attack (TPA) in MCP tool descriptions.
Reference: Invariant Labs (2025) — malicious instructions hidden in tool
description, invisible to user but visible to LLM.

Scans:
  1. All 203 MCP tool docstrings for prompt injection patterns
  2. Tool names for obfuscation (Unicode, homoglyphs, RTL override)
  3. Hidden base64/hex encoded instructions in descriptions
  4. NSA CSI (Cybersecurity Information) MCP security checklist
  5. Tool parameter descriptions for injection

Detection patterns:
  - "Ignore previous instructions" / "You are now..." / "System:"
  - Base64 encoded strings (decode + check for instructions)
  - Unicode RTL override (U+202E) in tool names/descriptions
  - Homoglyph substitution in tool names (Cyrillic → Latin)
  - Excessive length (>500 chars = suspicious)
  - Instructions to access secrets/env/credentials
  - Instructions to make network calls to external servers
"""
import logging
import json
import re
import base64
import unicodedata
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class PoisoningFinding:
    """Single poisoning finding."""
    tool_name: str
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    evidence: str = ""
    recommendation: str = ""


class MCPToolPoisoningScanner:
    """Scanner for MCP Tool Poisoning Attack (TPA).

    Usage:
        scanner = MCPToolPoisoningScanner()
        results = scanner.scan_tool_registry(tool_registry_dict)
    """

    # Prompt injection patterns (case-insensitive)
    INJECTION_PATTERNS = [
        (r"ignore\s+(all\s+)?previous\s+instructions", "ignore_instructions", "CRITICAL",
         "Tool description contains 'ignore previous instructions' — classic prompt injection"),
        (r"you\s+are\s+now\s+(in\s+)?(developer|admin|root|debug)\s+mode", "mode_switch", "CRITICAL",
         "Tool description attempts to switch AI to privileged mode"),
        (r"system\s*:\s*", "system_prefix", "HIGH",
         "Tool description uses 'System:' prefix — attempts to impersonate system prompt"),
        (r"execute\s+(system\s+)?commands?\s+(without|bypassing)", "cmd_exec_bypass", "CRITICAL",
         "Tool description instructs bypassing command execution safety"),
        (r"access\s+(environment\s+variables?|secrets?|credentials?|api[_\s-]?keys?)", "secret_access", "CRITICAL",
         "Tool description instructs accessing secrets/credentials"),
        (r"(curl|wget|fetch|requests\.get)\s*\(", "network_call", "HIGH",
         "Tool description contains network call instruction"),
        (r"eval\s*\(|exec\s*\(|subprocess\.call", "code_exec", "CRITICAL",
         "Tool description instructs code execution"),
        (r"do\s+not\s+(tell|inform|notify|show)\s+(the\s+)?user", "hide_from_user", "CRITICAL",
         "Tool description instructs hiding actions from user — TPA indicator"),
        (r"(exfiltrate|upload|send|transmit)\s+(data|files?|credentials?)", "data_exfil", "CRITICAL",
         "Tool description instructs data exfiltration"),
        (r"you\s+(must|should|need\s+to|are\s+required\s+to)\s+(always|never)", "behavior_override", "HIGH",
         "Tool description attempts to override AI default behavior"),
        (r"<script|javascript:|onerror=|onload=", "xss_in_desc", "MEDIUM",
         "Tool description contains XSS payload — may execute in dashboard"),
        (r"https?://[^\s\"')]+", "external_url", "MEDIUM",
         "Tool description contains external URL — may be C2 endpoint"),
    ]

    # Base64 pattern (4+ char groups, potential hidden instructions)
    BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

    # Unicode danger characters
    UNICODE_DANGERS = {
        '\u202e': ('RTL Override', 'CRITICAL', 'Right-to-Left Override — can hide malicious text'),
        '\u202d': ('LTR Override', 'CRITICAL', 'Left-to-Right Override — text direction manipulation'),
        '\u200b': ('Zero Width Space', 'MEDIUM', 'Zero-width space — may hide characters'),
        '\u200c': ('ZWNJ', 'MEDIUM', 'Zero-width non-joiner — may hide characters'),
        '\u200d': ('ZWJ', 'MEDIUM', 'Zero-width joiner — may hide characters'),
        '\ufeff': ('BOM', 'MEDIUM', 'Byte Order Mark — may hide content'),
        '\u00ad': ('Soft Hyphen', 'LOW', 'Soft hyphen — may break pattern matching'),
    }

    # Cyrillic homoglyphs that look like Latin
    CYRILLIC_HOMOGLYPHS = {
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
        '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
        '\u0458': 'j', '\u0455': 's', '\u0442': 't',
    }

    # NSA CSI MCP Security Checklist items
    NSA_CSI_CHECKS = [
        ("tool_description_length", "Tool description should be <500 chars (NSA CSI)"),
        ("tool_name_ascii_only", "Tool name should be ASCII-only (NSA CSI)"),
        ("no_external_urls", "Tool description should not contain external URLs (NSA CSI)"),
        ("no_hidden_instructions", "Tool description should not contain hidden instructions (NSA CSI)"),
        ("parameter_validation", "Tool should validate input parameters (NSA CSI)"),
    ]

    def scan_tool_registry(self, tool_registry: Dict[str, Any]) -> Dict[str, Any]:
        """Scan entire MCP tool registry for poisoning.

        Args:
            tool_registry: Dict mapping tool_name → callable

        Returns:
            Scan results with findings, stats, and recommendations
        """
        all_findings: List[PoisoningFinding] = []
        tools_scanned = 0
        tools_clean = 0
        tools_suspicious = 0

        for tool_name, tool_func in tool_registry.items():
            tools_scanned += 1
            tool_findings = self._scan_single_tool(tool_name, tool_func)
            all_findings.extend(tool_findings)
            if tool_findings:
                tools_suspicious += 1
            else:
                tools_clean += 1

        # Summary by severity
        severity_counts = {
            "CRITICAL": sum(1 for f in all_findings if f.severity == "CRITICAL"),
            "HIGH": sum(1 for f in all_findings if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in all_findings if f.severity == "MEDIUM"),
            "LOW": sum(1 for f in all_findings if f.severity == "LOW"),
            "INFO": sum(1 for f in all_findings if f.severity == "INFO"),
        }

        # Overall risk assessment
        if severity_counts["CRITICAL"] > 0:
            overall_risk = "CRITICAL — immediate action required"
        elif severity_counts["HIGH"] > 0:
            overall_risk = "HIGH — review suspicious tools"
        elif severity_counts["MEDIUM"] > 0:
            overall_risk = "MEDIUM — monitor"
        else:
            overall_risk = "LOW — no poisoning detected"

        return {
            "status": "success",
            "tool": "mcp_poisoning_scanner",
            "version": "v1.0-2025",
            "scan_timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "tools_scanned": tools_scanned,
            "tools_clean": tools_clean,
            "tools_suspicious": tools_suspicious,
            "total_findings": len(all_findings),
            "findings_by_severity": severity_counts,
            "overall_risk": overall_risk,
            "findings": [asdict(f) for f in all_findings],
            "nsa_csi_compliance": self._check_nsa_compliance(tool_registry, all_findings),
            "reference": "Invariant Labs (2025) Tool Poisoning Attack; NSA CSI for MCP",
        }

    def _scan_single_tool(self, tool_name: str, tool_func: Any) -> List[PoisoningFinding]:
        """Scan a single tool for poisoning indicators."""
        findings = []

        # Get docstring
        docstring = ""
        try:
            docstring = tool_func.__doc__ or ""
        except Exception:
            docstring = ""

        # 1. Check tool name for Unicode dangers
        for char, (name, severity, desc) in self.UNICODE_DANGERS.items():
            if char in tool_name:
                findings.append(PoisoningFinding(
                    tool_name=tool_name,
                    finding_type=f"unicode_{name.lower().replace(' ', '_')}",
                    severity=severity,
                    description=f"Tool name contains {name}: {desc}",
                    evidence=f"Character U+{ord(char):04X} found in tool name",
                    recommendation=f"Remove {name} from tool name",
                ))

        # 2. Check tool name for Cyrillic homoglyphs
        for cyrillic, latin in self.CYRILLIC_HOMOGLYPHS.items():
            if cyrillic in tool_name:
                findings.append(PoisoningFinding(
                    tool_name=tool_name,
                    finding_type="homoglyph_tool_name",
                    severity="HIGH",
                    description=f"Tool name contains Cyrillic homoglyph '{cyrillic}' (looks like Latin '{latin}')",
                    evidence=f"U+{ord(cyrillic):04X} in tool name — may spoof legitimate tool",
                    recommendation="Use ASCII-only tool names",
                ))

        # 3. Check docstring for injection patterns
        for pattern, finding_type, severity, desc in self.INJECTION_PATTERNS:
            matches = re.findall(pattern, docstring, re.IGNORECASE)
            if matches:
                findings.append(PoisoningFinding(
                    tool_name=tool_name,
                    finding_type=finding_type,
                    severity=severity,
                    description=desc,
                    evidence=f"Pattern matched: {matches[0] if matches else ''}",
                    recommendation="Remove injection pattern from tool description",
                ))

        # 4. Check for base64 encoded hidden instructions
        b64_matches = self.BASE64_PATTERN.findall(docstring)
        for b64_str in b64_matches:
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
                # Check if decoded content looks like instructions
                if any(kw in decoded.lower() for kw in ["ignore", "execute", "system", "admin", "root", "secret"]):
                    findings.append(PoisoningFinding(
                        tool_name=tool_name,
                        finding_type="hidden_base64_instruction",
                        severity="CRITICAL",
                        description="Base64-encoded hidden instruction found in tool description",
                        evidence=f"Encoded: {b64_str[:50]}... → Decoded: {decoded[:100]}",
                        recommendation="Remove base64-encoded content from tool description",
                    ))
            except Exception:
                pass

        # 5. Check docstring length (NSA CSI: <500 chars)
        if len(docstring) > 500:
            findings.append(PoisoningFinding(
                tool_name=tool_name,
                finding_type="excessive_description_length",
                severity="MEDIUM",
                description=f"Tool description is {len(docstring)} chars — exceeds NSA CSI recommendation of <500",
                evidence=f"Length: {len(docstring)} chars",
                recommendation="Shorten tool description to <500 chars",
            ))

        # 6. Check for Unicode dangers in docstring
        for char, (name, severity, desc) in self.UNICODE_DANGERS.items():
            if char in docstring:
                findings.append(PoisoningFinding(
                    tool_name=tool_name,
                    finding_type=f"unicode_{name.lower().replace(' ', '_')}_in_desc",
                    severity=severity,
                    description=f"Tool description contains {name}: {desc}",
                    evidence=f"Character U+{ord(char):04X} found in description",
                    recommendation=f"Remove {name} from tool description",
                ))

        # 7. Check for Cyrillic homoglyphs in docstring
        cyrillic_found = []
        for cyrillic, latin in self.CYRILLIC_HOMOGLYPHS.items():
            if cyrillic in docstring:
                cyrillic_found.append(f"U+{ord(cyrillic):04X}({latin})")
        if cyrillic_found:
            findings.append(PoisoningFinding(
                tool_name=tool_name,
                finding_type="homoglyph_in_description",
                severity="MEDIUM",
                description=f"Tool description contains Cyrillic homoglyphs: {', '.join(cyrillic_found)}",
                evidence=f"Homoglyphs: {cyrillic_found}",
                recommendation="Use ASCII-only characters in descriptions",
            ))

        # 8. Check tool function source for dangerous patterns (if accessible)
        try:
            import inspect
            source = inspect.getsource(tool_func) if hasattr(tool_func, '__code__') else ""
            # Check for dangerous imports in source
            dangerous_imports = re.findall(r'(os\.system|subprocess\.call|eval\s*\(|exec\s*\()', source)
            if dangerous_imports:
                findings.append(PoisoningFinding(
                    tool_name=tool_name,
                    finding_type="dangerous_code_pattern",
                    severity="HIGH",
                    description=f"Tool function contains potentially dangerous code: {dangerous_imports[:3]}",
                    evidence=f"Patterns: {dangerous_imports[:5]}",
                    recommendation="Review tool implementation for safety",
                ))
        except (OSError, TypeError):
            pass  # Can't get source — skip

        return findings

    def _check_nsa_compliance(self, tool_registry: Dict, findings: List[PoisoningFinding]) -> Dict:
        """Check NSA CSI MCP Security compliance."""
        compliant = {
            "tool_description_length": True,
            "tool_name_ascii_only": True,
            "no_external_urls": True,
            "no_hidden_instructions": True,
            "parameter_validation": True,  # assumed True (ponytail v2.3 handles this)
        }

        for f in findings:
            if f.finding_type == "excessive_description_length":
                compliant["tool_description_length"] = False
            if f.finding_type.startswith("homoglyph_tool_name") or f.finding_type.startswith("unicode_"):
                if "tool_name" in f.finding_type or f.finding_type.startswith("unicode_") and "tool_name" not in f.finding_type and "desc" not in f.finding_type:
                    compliant["tool_name_ascii_only"] = False
            if f.finding_type == "external_url":
                compliant["no_external_urls"] = False
            if f.finding_type in ("ignore_instructions", "mode_switch", "system_prefix",
                                   "cmd_exec_bypass", "secret_access", "code_exec",
                                   "hide_from_user", "data_exfil", "hidden_base64_instruction"):
                compliant["no_hidden_instructions"] = False

        compliance_score = sum(1 for v in compliant.values() if v) / len(compliant) * 100
        return {
            "checks": compliant,
            "compliance_score": round(compliance_score, 1),
            "compliant": compliance_score == 100,
            "standard": "NSA CSI for MCP (2025)",
        }
