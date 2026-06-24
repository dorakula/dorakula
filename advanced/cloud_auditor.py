#!/usr/bin/env python3
"""DORAKULA Cloud Native & Serverless Auditor.

Checks cloud metadata endpoints, IAM misconfigurations, and serverless issues.
"""
import logging, json
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class CloudAuditor:
    """Audit cloud infrastructure for misconfigurations."""

    METADATA_ENDPOINTS = {
        "aws_v1": "http://169.254.169.254/latest/meta-data/",
        "aws_v2": "http://169.254.169.254/latest/api/token",
        "gcp": "http://metadata.google.internal/computeMetadata/v1/",
        "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    }

    def check_metadata_ssrf(self, target_url: str) -> Dict:
        """Check if target is vulnerable to SSRF via cloud metadata."""
        findings = []
        for provider, endpoint in self.METADATA_ENDPOINTS.items():
            try:
                # Test if target URL can be manipulated to access metadata
                # This is a passive check — we test the target's SSRF endpoint
                # with the metadata URL as parameter
                if HAS_REQUESTS:
                    # Check if target has an SSRF parameter
                    ssrf_payloads = [
                        f"{target_url}?url={endpoint}",
                        f"{target_url}?target={endpoint}",
                        f"{target_url}?redirect={endpoint}",
                    ]
                    for payload in ssrf_payloads:
                        try:
                            resp = requests.get(payload, timeout=10, verify=False)
                            # Check if metadata was returned
                            if resp.status_code == 200:
                                body = resp.text[:500]
                                if any(k in body.lower() for k in ["ami-id", "instance-id", "iam", "security-credentials"]):
                                    findings.append({
                                        "provider": provider,
                                        "payload": payload[:100],
                                        "vulnerable": True,
                                        "severity": "CRITICAL",
                                        "evidence": body[:200],
                                    })
                        except Exception:
                            pass
            except Exception as e:
                logger.warning("Metadata check failed for %s: %s", provider, e)
        return {
            "check": "metadata_ssrf",
            "target": target_url,
            "findings": findings,
            "providers_tested": list(self.METADATA_ENDPOINTS.keys()),
        }

    def check_s3_bucket(self, bucket_name: str) -> Dict:
        """Check S3 bucket for public access."""
        findings = []
        if HAS_REQUESTS:
            urls = [
                f"https://{bucket_name}.s3.amazonaws.com/",
                f"https://s3.amazonaws.com/{bucket_name}/",
            ]
            for url in urls:
                try:
                    resp = requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        findings.append({
                            "url": url,
                            "status": "public_read",
                            "severity": "HIGH",
                            "snippet": resp.text[:200],
                        })
                    elif resp.status_code == 403:
                        findings.append({"url": url, "status": "private", "severity": "LOW"})
                    elif resp.status_code == 404:
                        findings.append({"url": url, "status": "not_found", "severity": "INFO"})
                except Exception as e:
                    findings.append({"url": url, "error": str(e)})
        return {"check": "s3_bucket", "bucket": bucket_name, "findings": findings}

    def check_k8s_dashboard(self, target: str) -> Dict:
        """Check for exposed Kubernetes dashboard."""
        findings = []
        if HAS_REQUESTS:
            k8s_urls = [
                f"{target}:30000",
                f"{target}:8001",
                f"{target}:8443",
                f"{target}:10250",
            ]
            for url in k8s_urls:
                try:
                    resp = requests.get(f"http://{url}", timeout=5)
                    if resp.status_code == 200 and "kubernetes" in resp.text.lower():
                        findings.append({"url": url, "status": "exposed", "severity": "CRITICAL"})
                except Exception:
                    pass
        return {"check": "k8s_dashboard", "target": target, "findings": findings}

    def full_audit(self, target: str) -> Dict:
        """Run all cloud audit checks."""
        return {
            "target": target,
            "metadata_ssrf": self.check_metadata_ssrf(target),
            "k8s_dashboard": self.check_k8s_dashboard(target),
        }
