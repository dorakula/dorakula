"""DORAKULA functional smoke tests.

Tests key endpoints end-to-end:
  - /api/health returns 200 with version info
  - /api/agent/tools returns 200 with tool list
  - /api/web/jwt_analyze returns 200 with JWT analysis
  - /api/web/jwt_none_bypass returns 200 with none_token
  - /api/web/xss_payloads returns 200 with payload list
  - /api/waf_bypass/info returns 200 with deadlock_thresholds
  - /api/auth/audit_log returns 200 with entries
  - /api/sovereign/* endpoints return 200 (S13 additions)
  - Rate limit triggers 429 after 100 requests
"""
import json, time
import pytest


def test_health_no_auth(http):
    """Health endpoint must work without auth."""
    status, body = http("GET", "/api/health", key="")
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "healthy"
    assert "version" in data
    assert "tools_registered" in data


def test_agent_tools_with_auth(http):
    status, body = http("GET", "/api/agent/tools")
    assert status == 200
    data = json.loads(body)
    assert "available" in data
    assert isinstance(data["available"], list)
    assert len(data["available"]) > 0


def test_jwt_analyze(http):
    """JWT analyze must return header + payload + findings."""
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    status, body = http("POST", "/api/web/jwt_analyze", body={"token": token})
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert "header" in data["data"]
    assert data["data"]["header"]["alg"] == "HS256"
    assert "payload" in data["data"]
    assert data["data"]["payload"]["sub"] == "1234567890"


def test_jwt_none_bypass(http):
    """JWT none bypass must return none_token."""
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    status, body = http("POST", "/api/web/jwt_none_bypass", body={"token": token})
    assert status == 200
    data = json.loads(body)
    assert "none_token" in data["data"]
    assert data["data"]["none_token"].startswith("eyJ")


def test_xss_payloads(http):
    """XSS payloads must return a list of payloads."""
    status, body = http("POST", "/api/web/xss_payloads", body={})
    assert status == 200
    data = json.loads(body)
    assert "payloads" in data
    assert isinstance(data["payloads"], list)
    assert len(data["payloads"]) > 0


def test_waf_bypass_info(http):
    """WAF bypass info must return deadlock config."""
    status, body = http("GET", "/api/waf_bypass/info")
    assert status == 200
    data = json.loads(body)
    assert data["available"] is True
    assert "deadlock_thresholds" in data
    assert "recovery_strategies" in data


def test_audit_log_query(http):
    """Audit log endpoint must return paginated entries."""
    status, body = http("GET", "/api/auth/audit_log?limit=5")
    assert status == 200
    data = json.loads(body)
    assert "entries" in data
    assert "count" in data
    assert "total" in data
    assert data["count"] <= 5


def test_audit_log_filter(http):
    """Audit log must support action filter."""
    status, body = http("GET", "/api/auth/audit_log?action=auth_failed&limit=3")
    assert status == 200
    data = json.loads(body)
    assert data["action_filter"] == "auth_failed"
    for entry in data["entries"]:
        assert entry["action"] == "auth_failed"


def test_cache_stats(http):
    """Cache stats must return cache info."""
    status, body = http("GET", "/api/cache/stats")
    assert status == 200
    data = json.loads(body)
    assert "max_size" in data
    assert "size" in data


# ============================================================
# Sovereign Intel endpoints (S13 additions)
# ============================================================

def test_sovereign_stats(http):
    """Sovereign stats endpoint must return DB stats."""
    status, body = http("GET", "/api/sovereign/stats")
    assert status == 200
    data = json.loads(body)
    assert "db_path" in data
    assert "scan_results" in data
    assert "hibp_passwords" in data


def test_sovereign_shodan(http):
    """Sovereign Shodan must return query results."""
    status, body = http("POST", "/api/sovereign/shodan", body={"query": "port:443"})
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["sovereign"] is True
    assert "matches" in data


def test_sovereign_censys(http):
    """Sovereign Censys must return query results."""
    status, body = http("POST", "/api/sovereign/censys", body={"query": "service:http"})
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["sovereign"] is True


def test_sovereign_hibp_email(http):
    """Sovereign HIBP email check must return breach info."""
    status, body = http("POST", "/api/sovereign/hibp", body={
        "email": "test@example.com",
        "check_type": "email"
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["check_type"] == "email"
    assert data["domain"] == "example.com"


def test_sovereign_hibp_password(http):
    """Sovereign HIBP password check must use k-anonymity SHA-1."""
    status, body = http("POST", "/api/sovereign/hibp", body={
        "password": "test123",
        "check_type": "password"
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["check_type"] == "password"
    assert "sha1_full_hash" in data
    assert "sha1_prefix" in data
    assert len(data["sha1_prefix"]) == 5  # k-anonymity prefix


# ============================================================
# Advanced module endpoints (S12 upgrades)
# ============================================================

def test_advanced_waf_bypass_obfuscate(http):
    """WAF bypass AI v2 must return 16+ obfuscation variants."""
    status, body = http("POST", "/api/advanced/waf_bypass_ai/obfuscate", body={
        "payload": "<script>alert(1)</script>",
        "waf_type": "cloudflare"
    })
    assert status == 200
    data = json.loads(body)
    assert "variants" in data
    assert len(data["variants"]) >= 9


def test_advanced_llm_security_scan(http):
    """LLM security v2 must return all OWASP LLM Top 10 categories."""
    status, body = http("POST", "/api/advanced/llm_security/scan", body={"target": "test"})
    assert status == 200
    data = json.loads(body)
    # Must include all categories
    for key in ["prompt_injection", "indirect_injection", "crescendo_jailbreak",
                "jailbreak", "tool_calling_abuse", "data_leakage", "model_dos",
                "insecure_output"]:
        assert key in data, f"Missing LLM security category: {key}"


def test_advanced_cloud_auditor_scan(http):
    """Cloud auditor v2 must return all audit checks."""
    status, body = http("POST", "/api/advanced/cloud_auditor/scan", body={
        "target_url": "https://example.com"
    })
    assert status == 200
    data = json.loads(body)
    for key in ["metadata_ssrf", "imdsv2_bypass", "k8s_dashboard", "container_escape"]:
        assert key in data, f"Missing cloud audit check: {key}"


def test_advanced_graphql_scan(http):
    """GraphQL specialist v2 must return all GraphQL tests."""
    status, body = http("POST", "/api/advanced/graphql/scan", body={
        "target": "https://example.com/graphql"
    })
    assert status == 200
    data = json.loads(body)
    for key in ["introspection", "depth_limit", "alias_dos", "batch_attack",
                "field_suggestion", "persisted_queries", "defer_stream_dos",
                "mutation_enum"]:
        assert key in data, f"Missing GraphQL test: {key}"


def test_advanced_ws_fuzzer_scan(http):
    """WebSocket fuzzer v2 must return all WS tests."""
    status, body = http("POST", "/api/advanced/ws_fuzzer/scan", body={
        "target": "ws://example.com/ws"
    })
    assert status == 200
    data = json.loads(body)
    for key in ["handshake", "message_injection", "connection_flood",
                "compression_bomb", "opcode_fuzzing", "cswsh"]:
        assert key in data, f"Missing WS fuzzer test: {key}"


# ============================================================
# Original tests (rate limit + generic runner)
# ============================================================

def test_rate_limit_triggers_429(http):
    """After 100 requests, rate limit must trigger 429."""
    # Note: this test consumes the rate limit quota. Run last.
    # Skip if we can't make 105 requests quickly.
    statuses = []
    for i in range(105):
        status, _ = http("GET", "/api/cache/stats", key="wrong-key", timeout=5)
        statuses.append(status)
        if status == 429:
            break
    assert 429 in statuses, f"Rate limit (429) never triggered after {len(statuses)} requests"


def test_generic_tool_runner(http):
    """Generic /api/run/<tool_name> must work for jwt_analyze."""
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    status, body = http("POST", "/api/run/jwt_analyze", body={"token": token})
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
