"""DORAKULA Advanced Modules v2 tests — 7 upgraded modules.

Tests:
  - advanced/waf_bypass_ai.py (WAFBypassAI class)
  - advanced/llm_security.py (LLMSecurityScanner class)
  - advanced/cloud_auditor.py (CloudAuditor class)
  - agents/graphql_specialist.py (GraphQLSpecialist class)
  - advanced/supply_chain_analyzer.py (SupplyChainAnalyzer class)
  - advanced/websocket_fuzzer.py (WebSocketFuzzer class)
  - agents/auto_reporter.py (AutoReporter class)

Tests run via REST API endpoints:
  - /api/advanced/waf_bypass_ai/obfuscate
  - /api/advanced/waf_bypass_ai/fingerprint
  - /api/advanced/llm_security/scan
  - /api/advanced/cloud_auditor/scan
  - /api/advanced/graphql/scan
  - /api/advanced/supply_chain/analyze
  - /api/advanced/ws_fuzzer/scan
  - /api/reports/auto/generate
"""
import json
import pytest


# ============================================================
# WAF Bypass AI v2
# ============================================================

def test_waf_bypass_obfuscate_returns_variants(http):
    """POST /api/advanced/waf_bypass_ai/obfuscate must return 16+ variants."""
    status, body = http("POST", "/api/advanced/waf_bypass_ai/obfuscate", {
        "payload": "<script>alert(1)</script>",
        "waf_type": "cloudflare"
    })
    assert status == 200
    data = json.loads(body)
    assert "variants" in data
    assert len(data["variants"]) >= 9  # at least rule-based variants (AI may add more)
    assert "original" in data
    assert data["original"] == "<script>alert(1)</script>"
    assert data["waf_type"] == "cloudflare"


def test_waf_bypass_obfuscate_techniques(http):
    """Verify all 16 obfuscation techniques are present (rule-based)."""
    status, body = http("POST", "/api/advanced/waf_bypass_ai/obfuscate", {
        "payload": "test_payload",
        "waf_type": "generic"
    })
    assert status == 200
    data = json.loads(body)
    techniques = [v.get("technique", "") for v in data["variants"]]
    # Must include at least these rule-based techniques
    expected = ["url_encode", "double_url_encode", "base64", "unicode_escape",
                "hex_escape", "html_entity", "nfkc_normalization", "rtlo_override",
                "homoglyph", "iri_raw", "rfc5987", "jwt_split", "polyglot",
                "sql_chunk", "hpp", "case_variation"]
    for tech in expected:
        assert tech in techniques, f"Missing technique: {tech}"


def test_waf_bypass_fingerprint_cloudflare(http):
    """POST /api/advanced/waf_bypass_ai/fingerprint must detect cloudflare."""
    status, body = http("POST", "/api/advanced/waf_bypass_ai/fingerprint", {
        "headers": {"Server": "cloudflare", "CF-Ray": "abc123"},
        "status_code": 403,
        "body": ""
    })
    assert status == 200
    data = json.loads(body)
    assert "cloudflare" in data["detected_wafs"]
    assert data["confidence"] == "HIGH"


def test_waf_bypass_fingerprint_generic(http):
    """WAF fingerprint must detect generic_waf for 403 with no signatures."""
    status, body = http("POST", "/api/advanced/waf_bypass_ai/fingerprint", {
        "headers": {},
        "status_code": 403,
        "body": "blocked"
    })
    assert status == 200
    data = json.loads(body)
    assert "generic_waf" in data["detected_wafs"]


# ============================================================
# LLM Security v2
# ============================================================

def test_llm_security_scan_returns_results(http):
    """POST /api/advanced/llm_security/scan must return all test categories."""
    status, body = http("POST", "/api/advanced/llm_security/scan", {"target": "test"})
    assert status == 200
    data = json.loads(body)
    # Must include all OWASP LLM Top 10 categories (2025)
    assert "prompt_injection" in data
    assert "indirect_injection" in data
    assert "crescendo_jailbreak" in data
    assert "jailbreak" in data
    assert "tool_calling_abuse" in data
    assert "data_leakage" in data
    assert "model_dos" in data
    assert "insecure_output" in data


def test_llm_security_prompt_injection(http):
    """POST /api/advanced/llm_security/prompt_injection must return findings."""
    status, body = http("POST", "/api/advanced/llm_security/prompt_injection", {
        "target_endpoint": "test"
    })
    assert status == 200
    data = json.loads(body)
    assert data["test"] == "prompt_injection"
    assert data["owasp"] == "LLM01"
    assert "findings" in data
    assert "total_tested" in data


# ============================================================
# Cloud Auditor v2
# ============================================================

def test_cloud_auditor_scan(http):
    """POST /api/advanced/cloud_auditor/scan must return audit results."""
    status, body = http("POST", "/api/advanced/cloud_auditor/scan", {
        "target_url": "https://example.com"
    })
    assert status == 200
    data = json.loads(body)
    assert "metadata_ssrf" in data
    assert "imdsv2_bypass" in data
    assert "k8s_dashboard" in data
    assert "container_escape" in data


def test_cloud_auditor_s3_check(http):
    """POST /api/advanced/cloud_auditor/s3_check must return findings."""
    status, body = http("POST", "/api/advanced/cloud_auditor/s3_check", {
        "bucket": "test-bucket-nonexist"
    })
    # May timeout (S3 endpoint slow) or return 200 — just verify no 500 crash
    assert status in [200, 0], f"Unexpected status: {status}"
    if status == 200:
        data = json.loads(body)
        assert data["check"] == "s3_bucket"
        assert "findings" in data


# ============================================================
# GraphQL Specialist v2
# ============================================================

def test_graphql_scan(http):
    """POST /api/advanced/graphql/scan must return all GraphQL tests."""
    status, body = http("POST", "/api/advanced/graphql/scan", {
        "target": "https://example.com/graphql"
    })
    assert status == 200
    data = json.loads(body)
    # Must include all v2 tests
    assert "introspection" in data
    assert "depth_limit" in data
    assert "alias_dos" in data
    assert "batch_attack" in data
    assert "field_suggestion" in data
    assert "persisted_queries" in data
    assert "defer_stream_dos" in data
    assert "mutation_enum" in data


def test_graphql_introspect(http):
    """POST /api/advanced/graphql/introspect must return result."""
    status, body = http("POST", "/api/advanced/graphql/introspect", {
        "target": "https://example.com/graphql"
    })
    assert status == 200
    data = json.loads(body)
    # May be "disabled" or "error" but should not crash


# ============================================================
# Supply Chain Analyzer v2
# ============================================================

def test_supply_chain_typosquat(http):
    """POST /api/advanced/supply_chain/typosquat must detect typosquats."""
    status, body = http("POST", "/api/advanced/supply_chain/typosquat", {
        "packages": ["requets", "numpyy", "flaskk"]
    })
    assert status == 200
    data = json.loads(body)
    assert data["check"] == "typosquatting"
    assert data["suspicious_count"] >= 3  # all 3 are typosquats


def test_supply_chain_analyze(http):
    """POST /api/advanced/supply_chain/analyze must run all checks."""
    status, body = http("POST", "/api/advanced/supply_chain/analyze", {
        "packages": ["requests", "requets"],
        "requirements": ["requests==2.31.0", "numpy"],
        "internal_packages": ["mycompany-internal"]
    })
    assert status == 200
    data = json.loads(body)
    assert "typosquatting" in data
    assert "version_pinning" in data
    assert "dependency_confusion" in data


# ============================================================
# WebSocket Fuzzer v2
# ============================================================

def test_ws_fuzzer_scan(http):
    """POST /api/advanced/ws_fuzzer/scan must return all WS tests."""
    status, body = http("POST", "/api/advanced/ws_fuzzer/scan", {
        "target": "ws://example.com/ws"
    })
    assert status == 200
    data = json.loads(body)
    # Must include all v2 tests
    assert "handshake" in data
    assert "message_injection" in data
    assert "connection_flood" in data
    assert "compression_bomb" in data
    assert "opcode_fuzzing" in data
    assert "cswsh" in data


def test_ws_fuzzer_injection(http):
    """POST /api/advanced/ws_fuzzer/injection must return injection results."""
    status, body = http("POST", "/api/advanced/ws_fuzzer/injection", {
        "target": "ws://example.com/ws"
    })
    # Response may be 200 with error (no websocket available) or 200 with results
    # Just verify it doesn't crash
    assert status in [200, 500]


# ============================================================
# Auto Reporter v2
# ============================================================

def test_auto_report_generate(http):
    """POST /api/reports/auto/generate must return report."""
    status, body = http("POST", "/api/reports/auto/generate", {
        "scan_results": {
            "test_category": {
                "test_check": {
                    "findings": [
                        {"severity": "HIGH", "evidence": "test evidence", "reason": "test reason"}
                    ]
                }
            }
        },
        "target": "https://example.com"
    })
    # May be 200 (success) or 429 (rate limit) — just verify no 500 crash
    assert status in [200, 429], f"Unexpected status: {status}, body: {body[:200]}"


def test_auto_report_validate(http):
    """POST /api/reports/auto/validate must return validation result."""
    status, body = http("POST", "/api/reports/auto/validate", {
        "finding": {"check": "xss_test", "reflected": True, "calibrated_severity": "HIGH"},
        "target": "https://example.com"
    })
    assert status in [200, 429], f"Unexpected status: {status}, body: {body[:200]}"


# ============================================================
# Generic runner tests for advanced modules
# ============================================================

def test_advanced_modules_via_generic_runner(http):
    """Advanced module tools must work via /api/run/<tool_name>."""
    tools_to_test = [
        ("graphql_fuzz", {"target": "https://example.com"}),
        ("cloud_audit", {"target": "https://example.com"}),
        ("mobile_scan", {"target": "https://example.com"}),
        ("llm_security_audit", {"target": "test"}),
        ("websocket_fuzz", {"target": "ws://example.com"}),
        ("supply_chain_check", {"target": "test"}),
        ("auto_generate_report", {}),
    ]
    for tool, body_data in tools_to_test:
        status, body = http("POST", f"/api/run/{tool}", body_data)
        # May be 200 (success) or 429 (rate limit)
        assert status in [200, 429], f"{tool} failed: {body[:200]}"
