"""DORAKULA functional smoke tests.

Tests key endpoints end-to-end:
  - /api/health returns 200 with version info
  - /api/agent/tools returns 200 with tool list
  - /api/web/jwt_analyze returns 200 with JWT analysis
  - /api/web/jwt_none_bypass returns 200 with none_token
  - /api/web/xss_payloads returns 200 with payload list
  - /api/waf_bypass/info returns 200 with deadlock_thresholds
  - /api/auth/audit_log returns 200 with entries
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
