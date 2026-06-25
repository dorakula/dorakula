#!/usr/bin/env python3
"""DORAKULA Supply Chain & Dependency Analyzer (v2 — 2025 upgrade).

Upgrades over v1:
  - SBOM parsing: CycloneDX JSON + SPDX (industry standard 2025).
  - Unicode confusable detection (homoglyphs in package names).
  - Malicious TLP patterns (post-install scripts, network calls, env exfil).
  - Prologue/epilogue injection in install scripts.
  - Pre/post-install script abuse detection.
  - Package.json "scripts" injection (npm).
  - Typosquatting: 30+ patterns (was 12) including Cyrillic lookalikes.
"""
import logging, json, re, unicodedata
from typing import Dict, List, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SupplyChainAnalyzer:
    """Analyze supply chain risks in dependencies and CI/CD (v2)."""

    POPULAR_PACKAGES = [
        "requests", "flask", "django", "numpy", "pandas", "scipy",
        "matplotlib", "tensorflow", "pytorch", "torch", "opencv-python",
        "pillow", "sqlalchemy", "celery", "redis", "pytest",
        "lodash", "express", "react", "axios", "moment",
        "chalk", "commander", "debug", "left-pad", "core-js",
    ]

    # 30+ patterns including Cyrillic confusables
    TYPOSQUAT_PATTERNS = [
        (r"^requets", "requests"), (r"^reqeusts", "requests"), (r"^request$", "requests"),
        (r"^flaskk", "flask"), (r"^fIask", "flask"),  # I is capital i
        (r"^djangoo", "django"), (r"^djngo", "django"), (r"^dijango", "django"),
        (r"^numpyy", "numpy"), (r"^numby", "numpy"), (r"^numPy", "numpy"),
        (r"^pandass", "pandas"), (r"^pndas", "pandas"),
        (r"^pytesst", "pytest"), (r"^pytst", "pytest"),
        (r"^reactt", "react"), (r"^raect", "react"),
        (r"^expres", "express"), (r"^expreess", "express"),
        (r"^lodahs", "lodash"), (r"^lodsh", "lodash"),
        (r"^axio", "axios"), (r"^axois", "axios"),
        (r"^chalkk", "chalk"), (r"^celry", "celery"),
        (r"^djang0", "django"), (r"^nump1y", "numpy"),
        (r"^requ3sts", "requests"), (r"^b0tstrap", "bootstrap"),
        (r"^m0ment", "moment"), (r"^expr3ss", "express"),
    ]

    # Cyrillic confusable characters (Latin → Cyrillic lookalike)
    CYRILLIC_CONFUSABLES = {
        "a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440",
        "c": "\u0441", "y": "\u0443", "x": "\u0445", "i": "\u0456",
        "j": "\u0458", "s": "\u0455", "t": "\u0442", "k": "\u043a",
        "m": "\u043c", "n": "\u043d", "r": "\u0440", "u": "\u0443",
    }

    # Malicious patterns in install scripts (TLP — Typosquat / Lateral / Prologue)
    MALICIOUS_INSTALL_PATTERNS = [
        (r"curl\s+http://[^\s]+\|\s*sh", "curl pipe sh — common malware pattern"),
        (r"wget\s+http://[^\s]+\|\s*sh", "wget pipe sh — common malware pattern"),
        (r"powershell.*-e\s+[A-Za-z0-9+/=]{20,}", "PowerShell encoded command"),
        (r"eval\s*\(.*base64_decode", "PHP eval base64 — backdoor"),
        (r"exec\s*\(.*\\x", "Python exec with hex — obfuscated payload"),
        (r"subprocess\.call\(.*curl", "Python subprocess curl — download exec"),
        (r"os\.system\(.*wget", "Python os.system wget — download exec"),
        (r"\bbase64\b.*\bdecode\b.*\bexec\b", "base64 decode exec chain"),
        (r"\$_GET\[|\$_POST\[|\$_REQUEST\[", "PHP superglobals — webshell"),
        (r"nc\s+-l.*-e\s+/bin/sh", "netcat reverse shell"),
        (r"/dev/tcp/\d+\.\d+\.\d+\.\d+/", "Bash /dev/tcp reverse shell"),
        (r"crontab.*\|.*sh", "Crontab persistence"),
        (r"\$\{\{.*secrets\.\w+", "GitHub Actions secrets exfil"),
        (r"process\.env\.[A-Z_]+", "Node.js env var exfil"),
        (r"os\.environ\.[A-Z_]+", "Python env var exfil"),
    ]

    # npm package.json "scripts" dangerous patterns
    NPM_DANGEROUS_SCRIPTS = [
        (r"preinstall.*curl", "preinstall curl — runs before install"),
        (r"postinstall.*curl", "postinstall curl — runs after install"),
        (r"preinstall.*wget", "preinstall wget"),
        (r"postinstall.*base64", "postinstall base64 — obfuscated"),
        (r"preinstall.*powershell", "preinstall powershell"),
    ]

    def check_typosquatting(self, package_names: List[str]) -> Dict:
        """Check for typosquatting including Unicode confusables (v2)."""
        findings = []
        for pkg in package_names:
            # Pattern-based check
            for pattern, legit in self.TYPOSQUAT_PATTERNS:
                if re.match(pattern, pkg.lower()):
                    findings.append({
                        "package": pkg,
                        "likely_typosquat_of": legit,
                        "severity": "HIGH",
                        "reason": f"Name closely resembles popular package '{legit}'",
                        "detection": "regex_pattern",
                    })
            # Unicode confusable check
            for latin, cyrillic in self.CYRILLIC_CONFUSABLES.items():
                if cyrillic in pkg:
                    # Find which legit package this might spoof
                    for legit in self.POPULAR_PACKAGES:
                        if latin in legit:
                            findings.append({
                                "package": pkg,
                                "likely_typosquat_of": legit,
                                "severity": "CRITICAL",
                                "reason": f"Cyrillic character {repr(cyrillic)} substitutes Latin '{latin}'",
                                "detection": "unicode_confusable",
                            })
                            break
        return {
            "check": "typosquatting",
            "version": "v2-2025",
            "packages_scanned": len(package_names),
            "findings": findings,
            "suspicious_count": len(findings),
        }

    def check_version_pinning(self, requirements: List[str]) -> Dict:
        """Check for unpinned dependencies (v2 — detect == vs >= vs ~=)."""
        unpinned = []
        weak_pinned = []
        for line in requirements:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not any(op in line for op in ["==", ">=", "~=", "<", ">", "==="]):
                unpinned.append(line)
            elif any(op in line for op in [">=", "~="]) and "==" not in line:
                weak_pinned.append(line)
        return {
            "check": "version_pinning",
            "version": "v2-2025",
            "total_deps": len([l for l in requirements if l.strip() and not l.startswith("#")]),
            "unpinned": unpinned,
            "weak_pinned": weak_pinned,
            "unpinned_count": len(unpinned),
            "weak_pinned_count": len(weak_pinned),
            "severity": "HIGH" if unpinned else ("MEDIUM" if weak_pinned else "LOW"),
        }

    def check_cicd_injection(self, workflow_files: Dict[str, str]) -> Dict:
        """Check CI/CD workflow files for injection vulnerabilities (v2)."""
        findings = []
        dangerous_patterns = [
            (r"\$\{\{.*github\.event.*\}\}", "GitHub Actions event injection via ${{ github.event }}"),
            (r"pull_request_target", "Dangerous use of pull_request_target trigger"),
            (r"\$\{\{.*env\..*\}\}", "Env var injection in workflow"),
            (r"\$\{\{.*github\.head_ref\}\}", "Branch name injection"),
            (r"\$\{\{.*github\.ref\}\}", "Ref injection"),
            (r"\$\{\{.*steps\..*\.outputs\.\w+\}\}", "Step output injection"),
            (r"run:.*\$\{\{", "Direct interpolation in run: block — high risk"),
            (r"actions/checkout@v1", "Outdated checkout action (no ref pinning)"),
            (r"actions/checkout@v2", "Outdated checkout action (v2)"),
        ]
        for filename, content in workflow_files.items():
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, content):
                    findings.append({"file": filename, "issue": desc, "severity": "HIGH" if "run:" in desc or "pull_request_target" in desc else "MEDIUM"})
        return {
            "check": "cicd_injection",
            "version": "v2-2025",
            "files_scanned": len(workflow_files),
            "findings": findings,
        }

    def check_dependency_confusion(self, internal_packages: List[str]) -> Dict:
        """Check if internal package names could be overwritten (v2)."""
        findings = []
        if HAS_REQUESTS:
            for pkg in internal_packages:
                # Check PyPI
                try:
                    resp = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=5)
                    if resp.status_code == 200:
                        data = resp.json()
                        findings.append({
                            "package": pkg,
                            "public_registry": "pypi",
                            "vulnerable": True,
                            "severity": "HIGH",
                            "reason": "Internal package name exists on public PyPI — dependency confusion possible",
                            "public_version": data.get("info", {}).get("version", "unknown"),
                        })
                except Exception:
                    pass
                # Check npm
                try:
                    resp = requests.get(f"https://registry.npmjs.org/{pkg}", timeout=5)
                    if resp.status_code == 200:
                        data = resp.json()
                        latest = data.get("dist-tags", {}).get("latest", "unknown")
                        findings.append({
                            "package": pkg,
                            "public_registry": "npm",
                            "vulnerable": True,
                            "severity": "HIGH",
                            "reason": "Internal package name exists on public npm — dependency confusion possible",
                            "public_version": latest,
                        })
                except Exception:
                    pass
        return {
            "check": "dependency_confusion",
            "version": "v2-2025",
            "packages_checked": len(internal_packages),
            "findings": findings,
        }

    def check_install_scripts(self, package_files: Dict[str, str]) -> Dict:
        """Check install scripts for malicious patterns (v2 — TLP detection)."""
        findings = []
        for filename, content in package_files.items():
            for pattern, desc in self.MALICIOUS_INSTALL_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.append({
                        "file": filename,
                        "issue": desc,
                        "severity": "CRITICAL" if "shell" in desc.lower() or "eval" in desc.lower() else "HIGH",
                        "matches": len(matches),
                        "sample_match": matches[0][:100] if matches else "",
                    })
            # npm-specific
            if filename.endswith("package.json"):
                try:
                    pkg = json.loads(content)
                    scripts = pkg.get("scripts", {})
                    for script_name, script_content in scripts.items():
                        for pattern, desc in self.NPM_DANGEROUS_SCRIPTS:
                            if re.search(pattern, script_content, re.IGNORECASE):
                                findings.append({
                                    "file": filename,
                                    "script": script_name,
                                    "issue": desc,
                                    "severity": "CRITICAL",
                                    "match": script_content[:100],
                                })
                except json.JSONDecodeError:
                    pass
        return {
            "check": "install_scripts",
            "version": "v2-2025",
            "files_scanned": len(package_files),
            "findings": findings,
        }

    def parse_sbom(self, sbom_content: str, format: str = "auto") -> Dict:
        """Parse SBOM (CycloneDX or SPDX) for component inventory (v2 — 2025)."""
        try:
            data = json.loads(sbom_content)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}

        detected_format = format
        if format == "auto":
            if "bomFormat" in data:
                detected_format = "cyclonedx"
            elif "SPDXID" in data:
                detected_format = "spdx"
            else:
                return {"error": "Unknown SBOM format"}

        components = []
        if detected_format == "cyclonedx":
            for comp in data.get("components", []):
                components.append({
                    "name": comp.get("name"),
                    "version": comp.get("version"),
                    "type": comp.get("type"),
                    "purl": comp.get("purl"),
                    "bom_ref": comp.get("bom-ref"),
                })
        elif detected_format == "spdx":
            for comp in data.get("packages", []):
                components.append({
                    "name": comp.get("name"),
                    "version": comp.get("versionInfo"),
                    "type": "spdx-" + str(comp.get("type", "")),
                    "purl": None,
                    "license": comp.get("licenseConcluded") or comp.get("licenseDeclared"),
                })

        # Run typosquat + version pinning checks on components
        names = [c["name"] for c in components if c.get("name")]
        return {
            "check": "sbom_parse",
            "version": "v2-2025",
            "format": detected_format,
            "total_components": len(components),
            "components_sample": components[:10],
            "typosquat_check": self.check_typosquatting(names),
        }



    # ponytail: merged from supply_chain_auditor.py (deleted — consolidation)
    # Runtime JS audit data (complements dependency analysis)

    VULNERABLE_LIBS = {
        "jquery": [
            {"version_range": "<3.5.0", "cve": "CVE-2020-11022", "severity": "medium", "description": "XSS via .html() method"},
            {"version_range": "<3.4.1", "cve": "CVE-2019-11358", "severity": "medium", "description": "Prototype pollution via .extend()"},
        ],
        "lodash": [
            {"version_range": "<4.17.21", "cve": "CVE-2021-23337", "severity": "high", "description": "Command injection via template"},
            {"version_range": "<4.17.19", "cve": "CVE-2020-8203", "severity": "high", "description": "Prototype pollution via zipObjectDeep"},
        ],
        "angular": [
            {"version_range": "<1.8.0", "cve": "CVE-2020-7676", "severity": "high", "description": "XSS via animator"},
        ],
        "react": [
            {"version_range": "<16.5.2", "cve": "CVE-2018-6341", "severity": "high", "description": "ReDoS vulnerability"},
        ],
        "moment": [
            {"version_range": "<2.29.2", "cve": "CVE-2022-24785", "severity": "high", "description": "ReDoS in parse()"},
        ],
    }

    API_KEY_PATTERNS = [
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
        (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        (r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", "JWT token"),
        (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
        (r"xox[baprs]-[a-zA-Z0-9-]+", "Slack token"),
    ]

    def audit_runtime_js(self, js_content: str) -> Dict:
        """ponytail: merged from supply_chain_auditor. Audit JS for vulnerable libs + API keys."""
        findings = []
        # Check for vulnerable library versions
        for lib, vulns in self.VULNERABLE_LIBS.items():
            if lib.lower() in js_content.lower():
                for v in vulns:
                    findings.append({
                        "type": "vulnerable_library",
                        "library": lib,
                        "cve": v["cve"],
                        "severity": v["severity"],
                        "description": v["description"],
                    })
        # Check for exposed API keys
        import re
        for pattern, label in self.API_KEY_PATTERNS:
            matches = re.findall(pattern, js_content)
            if matches:
                findings.append({
                    "type": "exposed_api_key",
                    "key_type": label,
                    "count": len(matches),
                    "severity": "critical",
                    "sample": matches[0][:20] + "...",
                })
        return {"check": "runtime_js_audit", "findings": findings, "findings_count": len(findings)}

    def check_sri(self, html: str) -> Dict:
        """ponytail: merged from supply_chain_auditor. Check Subresource Integrity attributes."""
        import re
        scripts = re.findall(r'<script[^>]+src="([^"]+)"[^>]*>', html)
        missing_sri = []
        for src in scripts:
            if "integrity=" not in html:
                missing_sri.append(src)
        return {
            "check": "sri_check",
            "scripts_found": len(scripts),
            "missing_sri": missing_sri,
            "severity": "medium" if missing_sri else "low",
        }

    def full_analysis(self, package_names: List[str] = None, requirements: List[str] = None,
                      workflow_files: Dict = None, internal_packages: List[str] = None,
                      package_files: Dict = None, sbom: str = None) -> Dict:
        """Run all supply chain checks (v2)."""
        results = {"version": "v2-2025"}
        if package_names:
            results["typosquatting"] = self.check_typosquatting(package_names)
        if requirements:
            results["version_pinning"] = self.check_version_pinning(requirements)
        if workflow_files:
            results["cicd_injection"] = self.check_cicd_injection(workflow_files)
        if internal_packages:
            results["dependency_confusion"] = self.check_dependency_confusion(internal_packages)
        if package_files:
            results["install_scripts"] = self.check_install_scripts(package_files)
        if sbom:
            results["sbom"] = self.parse_sbom(sbom)
        return results
