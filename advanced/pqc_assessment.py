#!/usr/bin/env python3
"""DORAKULA PQC Migration Assessment Module — P0 #9 from audit.

NIST PQC standards finalized (FIPS 203/204/205, Aug 2024).
NSA ordered PQC inventory for National Security Systems.
CycloneDX CBOM (Cryptography Bill of Materials) standardized.

Reference: NIST PQC (https://csrc.nist.gov/projects/post-quantum-cryptography)
"""
import logging, json, re
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class PQCAssessment:
    """Assess post-quantum cryptography migration readiness."""

    # Quantum-vulnerable algorithms (broken by Shor's algorithm)
    VULNERABLE_ALGORITHMS = {
        "RSA": {"risk": "CRITICAL", "replacement": "CRYSTALS-Dilithium (FIPS 204)", "timeline": "2025-2030"},
        "ECDSA": {"risk": "CRITICAL", "replacement": "CRYSTALS-Dilithium (FIPS 204)", "timeline": "2025-2030"},
        "ECDH": {"risk": "CRITICAL", "replacement": "CRYSTALS-Kyber (FIPS 203)", "timeline": "2025-2030"},
        "DH": {"risk": "CRITICAL", "replacement": "CRYSTALS-Kyber (FIPS 203)", "timeline": "2025-2028"},
        "DSA": {"risk": "CRITICAL", "replacement": "CRYSTALS-Dilithium (FIPS 204)", "timeline": "2025-2028"},
        "Ed25519": {"risk": "HIGH", "replacement": "CRYSTALS-Dilithium + Ed25519 hybrid", "timeline": "2027-2030"},
        "X25519": {"risk": "HIGH", "replacement": "Kyber768 + X25519 hybrid (RFC 9180)", "timeline": "2027-2030"},
    }

    # Quantum-safe algorithms (resistant to Shor + Grover)
    SAFE_ALGORITHMS = {
        "AES-256": {"status": "SAFE", "note": "Grover reduces to 128-bit — still safe"},
        "AES-128": {"status": "CAUTION", "note": "Grover reduces to 64-bit — marginal"},
        "SHA-256": {"status": "SAFE", "note": "Grover reduces to 128-bit — still safe"},
        "SHA-384": {"status": "SAFE"},
        "SHA-512": {"status": "SAFE"},
        "SHA-3": {"status": "SAFE"},
        "HMAC-SHA256": {"status": "SAFE"},
        "ChaCha20": {"status": "SAFE", "note": "256-bit key, Grover-safe"},
        "Poly1305": {"status": "SAFE"},
        "CRYSTALS-Kyber": {"status": "PQC-STANDARD", "note": "FIPS 203 (ML-KEM)"},
        "CRYSTALS-Dilithium": {"status": "PQC-STANDARD", "note": "FIPS 204 (ML-DSA)"},
        "SPHINCS+": {"status": "PQC-STANDARD", "note": "FIPS 205 (SLH-DSA)"},
    }

    def assess_codebase(self, source_files: Dict[str, str] = None,
                       dependencies: List[str] = None) -> Dict[str, Any]:
        """Assess codebase for PQC migration readiness."""
        findings = []
        crypto_usage = {}

        # Scan source files for crypto patterns
        if source_files:
            for filename, content in source_files.items():
                found = self._scan_for_crypto(filename, content)
                crypto_usage[filename] = found
                for algo in found:
                    if algo in self.VULNERABLE_ALGORITHMS:
                        info = self.VULNERABLE_ALGORITHMS[algo]
                        findings.append({
                            "file": filename,
                            "algorithm": algo,
                            "risk": info["risk"],
                            "replacement": info["replacement"],
                            "timeline": info["timeline"],
                            "severity": info["risk"],
                            "description": f"Quantum-vulnerable algorithm '{algo}' found in {filename}",
                        })

        # Scan dependencies
        if dependencies:
            for dep in dependencies:
                dep_lower = dep.lower()
                if any(v.lower() in dep_lower for v in self.VULNERABLE_ALGORITHMS):
                    findings.append({
                        "dependency": dep,
                        "risk": "HIGH",
                        "description": f"Dependency may use quantum-vulnerable crypto: {dep}",
                    })

        # Generate CBOM (Cryptography Bill of Materials)
        cbom = self._generate_cbom(crypto_usage, findings)

        # Overall readiness
        vuln_count = len(findings)
        readiness = (
            "NOT_READY" if vuln_count > 5
            else "PARTIAL" if vuln_count > 0
            else "READY"
        )

        return {
            "status": "success",
            "tool": "pqc_assessment",
            "vulnerable_findings": vuln_count,
            "readiness": readiness,
            "findings": findings,
            "cbom": cbom,
            "safe_algorithms_detected": [a for a in self.SAFE_ALGORITHMS if any(a.lower() in str(v) for v in crypto_usage.values())],
            "reference": "NIST FIPS 203/204/205, NSA PQC memo, CycloneDX CBOM",
        }

    def _scan_for_crypto(self, filename: str, content: str) -> List[str]:
        """Scan file content for crypto algorithm usage."""
        found = set()
        patterns = {
            "RSA": [r"RSA", r"rsa.generate", r"from.*import.*RSA"],
            "ECDSA": [r"ECDSA", r"ecdsa.sign", r"ecdsa.verify"],
            "ECDH": [r"ECDH", r"ecdh", r"elliptic.*curve.*diffie"],
            "Ed25519": [r"Ed25519", r"ed25519"],
            "X25519": [r"X25519", r"x25519"],
            "AES-256": [r"AES.256", r"aes_256", r"AES.GCM.*256"],
            "AES-128": [r"AES.128", r"aes_128"],
            "SHA-256": [r"sha256", r"SHA-256", r"hashlib.sha256"],
            "SHA-3": [r"sha3", r"SHA-3", r"hashlib.sha3"],
            "ChaCha20": [r"ChaCha20", r"chacha20"],
            "CRYSTALS-Kyber": [r"Kyber", r"kyber", r"ML-KEM"],
            "CRYSTALS-Dilithium": [r"Dilithium", r"dilithium", r"ML-DSA"],
        }
        for algo, pats in patterns.items():
            for pat in pats:
                if re.search(pat, content, re.IGNORECASE):
                    found.add(algo)
                    break
        return list(found)

    def _generate_cbom(self, usage: Dict, findings: List) -> Dict:
        """Generate CycloneDX CBOM (Cryptography Bill of Materials)."""
        all_algos = set()
        for algos in usage.values():
            all_algos.update(algos)
        components = []
        for algo in all_algos:
            info = self.VULNERABLE_ALGORITHMS.get(algo, self.SAFE_ALGORITHMS.get(algo, {"status": "UNKNOWN"}))
            components.append({
                "name": algo,
                "type": "cryptographic-asset",
                "properties": [
                    {"name": "quantum_safe", "value": str(algo not in self.VULNERABLE_ALGORITHMS)},
                    {"name": "status", "value": info.get("status", info.get("risk", "UNKNOWN"))},
                    {"name": "replacement", "value": info.get("replacement", "N/A")},
                ],
            })
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "type": "cbom",
            "components": components,
        }
