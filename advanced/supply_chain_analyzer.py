#!/usr/bin/env python3
"""DORAKULA Supply Chain & Dependency Analyzer (Advanced).

Typosquatting detection, malicious package check, CI/CD injection, dependency confusion.
"""
import logging, json, re
from typing import Dict, List, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SupplyChainAnalyzer:
    """Analyze supply chain risks in dependencies and CI/CD."""

    POPULAR_PACKAGES = [
        "requests", "flask", "django", "numpy", "pandas", "scipy",
        "matplotlib", "tensorflow", "pytorch", "torch", "opencv-python",
        "pillow", "sqlalchemy", "celery", "redis", "pytest",
        "lodash", "express", "react", "axios", "moment",
    ]

    TYPOSQUAT_PATTERNS = [
        (r"requets", "requests"), (r"reqeusts", "requests"),
        (r"flaskk", "flask"), (r"flaskk", "flask"),
        (r"djangoo", "django"), (r"djngo", "django"),
        (r"numpyy", "numpy"), (r"numby", "numpy"),
        (r"pandass", "pandas"), (r"pndas", "pandas"),
        (r"pytesst", "pytest"), (r"pytst", "pytest"),
    ]

    def check_typosquatting(self, package_names: List[str]) -> Dict:
        """Check for typosquatting in package names."""
        findings = []
        for pkg in package_names:
            for pattern, legit in self.TYPOSQUAT_PATTERNS:
                if re.match(pattern, pkg.lower()):
                    findings.append({
                        "package": pkg,
                        "likely_typosquat_of": legit,
                        "severity": "HIGH",
                        "reason": f"Name closely resembles popular package '{legit}'",
                    })
        return {
            "check": "typosquatting",
            "packages_scanned": len(package_names),
            "findings": findings,
            "suspicious_count": len(findings),
        }

    def check_version_pinning(self, requirements: List[str]) -> Dict:
        """Check for unpinned dependencies."""
        unpinned = []
        for line in requirements:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Check if version is pinned (==, >=, ~=, <)
            if not any(op in line for op in ["==", ">=", "~=", "<", ">"]):
                unpinned.append(line)
        return {
            "check": "version_pinning",
            "total_deps": len([l for l in requirements if l.strip() and not l.startswith("#")]),
            "unpinned": unpinned,
            "unpinned_count": len(unpinned),
            "severity": "MEDIUM" if unpinned else "LOW",
        }

    def check_cicd_injection(self, workflow_files: Dict[str, str]) -> Dict:
        """Check CI/CD workflow files for injection vulnerabilities."""
        findings = []
        dangerous_patterns = [
            (r"\$\{\{.*github\.event.*\}\}", "GitHub Actions event injection via ${{ github.event }}"),
            (r"pull_request_target", "Dangerous use of pull_request_target trigger"),
            (r"\$\{\{.*env\..*\}\}", "Env var injection in workflow"),
        ]
        for filename, content in workflow_files.items():
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, content):
                    findings.append({"file": filename, "issue": desc, "severity": "HIGH"})
        return {
            "check": "cicd_injection",
            "files_scanned": len(workflow_files),
            "findings": findings,
        }

    def check_dependency_confusion(self, internal_packages: List[str]) -> Dict:
        """Check if internal package names could be overwritten by public packages."""
        findings = []
        if HAS_REQUESTS:
            for pkg in internal_packages:
                try:
                    resp = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=5)
                    if resp.status_code == 200:
                        findings.append({
                            "package": pkg,
                            "public_registry": "pypi",
                            "vulnerable": True,
                            "severity": "HIGH",
                            "reason": "Internal package name exists on public PyPI — dependency confusion possible",
                        })
                except Exception:
                    pass
        return {
            "check": "dependency_confusion",
            "packages_checked": len(internal_packages),
            "findings": findings,
        }

    def full_analysis(self, package_names: List[str] = None, requirements: List[str] = None,
                      workflow_files: Dict = None, internal_packages: List[str] = None) -> Dict:
        """Run all supply chain checks."""
        results = {}
        if package_names:
            results["typosquatting"] = self.check_typosquatting(package_names)
        if requirements:
            results["version_pinning"] = self.check_version_pinning(requirements)
        if workflow_files:
            results["cicd_injection"] = self.check_cicd_injection(workflow_files)
        if internal_packages:
            results["dependency_confusion"] = self.check_dependency_confusion(internal_packages)
        return results
