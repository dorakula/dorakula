"""DORAKULA Sovereign Intelligence tests — 5 sovereign tools.

Tests:
  - /api/sovereign/stats (GET)
  - /api/sovereign/shodan (POST, query cache)
  - /api/sovereign/censys (POST, query cache)
  - /api/sovereign/hibp (POST, email + password modes)
  - /api/sovereign/hibp_import (POST, breach catalogue import)

Sovereignty compliance (per SOVEREIGN-CYBER-FORGE V2):
  - No API keys required
  - 100% local processing
  - All queries stay in local SQLite
"""
import json
import pytest
import hashlib


# ============================================================
# /api/sovereign/stats
# ============================================================

def test_sovereign_stats_returns_200(http):
    """GET /api/sovereign/stats must return 200 with DB stats."""
    status, body = http("GET", "/api/sovereign/stats")
    assert status == 200
    data = json.loads(body)
    assert "db_path" in data
    assert "db_size_bytes" in data
    assert "scan_results" in data
    assert "unique_ips" in data
    assert "hibp_passwords" in data
    assert "hibp_breaches" in data


def test_sovereign_stats_requires_auth(http):
    """GET /api/sovereign/stats without API key must return 401."""
    status, body = http("GET", "/api/sovereign/stats", key="")
    assert status == 401


# ============================================================
# /api/sovereign/shodan
# ============================================================

def test_sovereign_shodan_query_only(http):
    """POST /api/sovereign/shodan with query only (no scan) must return 200."""
    status, body = http("POST", "/api/sovereign/shodan", {"query": "port:443"})
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["tool"] == "sovereign_shodan"
    assert data["sovereign"] is True
    assert "matches" in data
    assert "total" in data
    assert "scanned_new_hosts" in data


def test_sovereign_shodan_query_syntax(http):
    """Test Shodan-like query syntax: port:80 service:http."""
    for query in ["port:443", "service:http", "product:nginx", "banner:apache"]:
        status, body = http("POST", "/api/sovereign/shodan", {"query": query})
        assert status == 200, f"Query {query} failed: {body[:200]}"
        data = json.loads(body)
        assert data["status"] == "success"


def test_sovereign_shodan_requires_auth(http):
    """POST /api/sovereign/shodan without API key must return 401."""
    status, body = http("POST", "/api/sovereign/shodan", {"query": "port:443"}, key="")
    assert status == 401


# ============================================================
# /api/sovereign/censys
# ============================================================

def test_sovereign_censys_query_only(http):
    """POST /api/sovereign/censys with query only must return 200."""
    status, body = http("POST", "/api/sovereign/censys", {"query": "service:ssh"})
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["tool"] == "sovereign_censys"
    assert data["sovereign"] is True


def test_sovereign_censys_requires_auth(http):
    """POST /api/sovereign/censys without API key must return 401."""
    status, body = http("POST", "/api/sovereign/censys", {"query": "port:22"}, key="")
    assert status == 401


# ============================================================
# /api/sovereign/hibp
# ============================================================

def test_sovereign_hibp_email_check(http):
    """POST /api/sovereign/hibp with email check_type must return 200."""
    status, body = http("POST", "/api/sovereign/hibp", {
        "email": "test@example.com",
        "check_type": "email"
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["tool"] == "sovereign_hibp"
    assert data["check_type"] == "email"
    assert data["email"] == "test@example.com"
    assert data["domain"] == "example.com"
    assert "breach_count" in data
    assert "breaches" in data


def test_sovereign_hibp_password_check_k_anonymity(http):
    """POST /api/sovereign/hibp with password check_type must return 200 with k-anonymity.

    Per NIST FIPS 180-4: SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    """
    status, body = http("POST", "/api/sovereign/hibp", {
        "password": "password",
        "check_type": "password"
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["check_type"] == "password"
    
    # Verify SHA-1 hash computed correctly (NIST FIPS 180-4)
    expected_sha1 = hashlib.sha1(b"password").hexdigest().upper()
    assert data["sha1_full_hash"] == expected_sha1
    assert data["sha1_full_hash"] == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    
    # Verify k-anonymity: prefix is 5 chars
    assert data["sha1_prefix"] == expected_sha1[:5]
    assert len(data["sha1_prefix"]) == 5
    
    # Verify other fields
    assert "pwned" in data
    assert "breach_count" in data
    assert "k_anonymity_suffixes_returned" in data


def test_sovereign_hibp_invalid_email(http):
    """POST /api/sovereign/hibp with invalid email must return error."""
    status, body = http("POST", "/api/sovereign/hibp", {
        "email": "invalid-email-no-at-sign",
        "check_type": "email"
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "error"
    assert "invalid email format" in data["error"].lower()


def test_sovereign_hibp_invalid_check_type(http):
    """POST /api/sovereign/hibp with invalid check_type must return error."""
    status, body = http("POST", "/api/sovereign/hibp", {
        "email": "test@example.com",
        "check_type": "invalid_type"
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "error"
    assert "invalid check_type" in data["error"].lower()


def test_sovereign_hibp_requires_auth(http):
    """POST /api/sovereign/hibp without API key must return 401."""
    status, body = http("POST", "/api/sovereign/hibp", {
        "email": "test@example.com",
        "check_type": "email"
    }, key="")
    assert status == 401


# ============================================================
# /api/sovereign/hibp_import
# ============================================================

def test_sovereign_hibp_import_breaches(http):
    """POST /api/sovereign/hibp_import with breach catalogue must import successfully."""
    breaches = [
        {
            "Name": "TestBreach",
            "Title": "Test Breach",
            "Domain": "testbreach.com",
            "BreachDate": "2024-01-01",
            "PwnCount": 1000,
            "DataClasses": ["Email addresses", "Passwords"],
            "Description": "Test breach for unit testing"
        }
    ]
    status, body = http("POST", "/api/sovereign/hibp_import", {
        "breaches_json": json.dumps(breaches)
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["imported_breaches"] >= 1


def test_sovereign_hibp_import_no_args(http):
    """POST /api/sovereign/hibp_import with no args must return error."""
    status, body = http("POST", "/api/sovereign/hibp_import", {})
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "error"
    assert "either file_path or breaches_json required" in data["error"]


def test_sovereign_hibp_import_nonexistent_file(http):
    """POST /api/sovereign/hibp_import with non-existent file must return error."""
    status, body = http("POST", "/api/sovereign/hibp_import", {
        "file_path": "/tmp/nonexistent_xyz123.txt"
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "error"
    assert "file not found" in data["error"].lower()


def test_sovereign_hibp_import_invalid_json(http):
    """POST /api/sovereign/hibp_import with invalid JSON must return error."""
    status, body = http("POST", "/api/sovereign/hibp_import", {
        "breaches_json": "not-valid-json"
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "error"


# ============================================================
# Generic runner tests (/api/run/<tool_name>)
# ============================================================

def test_sovereign_shodan_via_generic_runner(http):
    """POST /api/run/sovereign_shodan must work via generic runner."""
    status, body = http("POST", "/api/run/sovereign_shodan", {"query": "port:80"})
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"
    assert data["tool"] == "sovereign_shodan"


def test_sovereign_censys_via_generic_runner(http):
    """POST /api/run/sovereign_censys must work via generic runner."""
    status, body = http("POST", "/api/run/sovereign_censys", {"query": "service:http"})
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"


def test_sovereign_hibp_via_generic_runner(http):
    """POST /api/run/sovereign_hibp must work via generic runner."""
    status, body = http("POST", "/api/run/sovereign_hibp", {
        "email_or_password": "test@example.com",
        "check_type": "email"
    })
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "success"


# ============================================================
# Sovereignty compliance tests
# ============================================================

def test_sovereign_tools_no_api_key_in_response(http):
    """Sovereign tools must NOT require or expose API keys."""
    for endpoint, body in [
        ("/api/sovereign/stats", None),
        ("/api/sovereign/shodan", {"query": "port:443"}),
        ("/api/sovereign/censys", {"query": "service:http"}),
        ("/api/sovereign/hibp", {"email": "test@example.com", "check_type": "email"}),
    ]:
        method = "GET" if body is None else "POST"
        status, resp = http(method, endpoint, body)
        assert status == 200, f"{endpoint} failed"
        # Verify response has sovereign=True flag
        data = json.loads(resp)
        if isinstance(data, dict) and "sovereign" in data:
            assert data["sovereign"] is True, f"{endpoint} not sovereign"
        # Verify no API key field exposed
        resp_str = str(data)
        assert "api_key" not in resp_str.lower(), f"{endpoint} exposes api_key"
        assert "shodan_api_key" not in resp_str.lower()
        assert "censys_api_id" not in resp_str.lower()
        assert "hibp_api_key" not in resp_str.lower()
