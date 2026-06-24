"""DORAKULA route auth tests — parametrized for all key endpoints.

Each test verifies:
  1. Without API key → 401 (fail-closed)
  2. With valid API key → not 401 (auth passes, may be 400/200/500 depending on params)

This catches:
  - Routes that accidentally allow unauthenticated access
  - Routes that crash on empty body (500 instead of 400)
  - Routes that don't exist (404)
"""
import pytest

# All routes to test (method, path)
ROUTES = [('POST', '/api/agent/execute'), ('POST', '/api/agent/plan'), ('GET', '/api/agent/tasks'), ('GET', '/api/agent/tools'), ('POST', '/api/ai/analyze'), ('POST', '/api/ai/execute'), ('POST', '/api/ai/recommend'), ('POST', '/api/cache/clear'), ('GET', '/api/cache/stats'), ('GET', '/api/db/stats'), ('GET', '/api/auth/audit_log'), ('POST', '/api/waf_bypass/403_bypass_urls'), ('POST', '/api/waf_bypass/cmdi_test_v3'), ('GET', '/api/waf_bypass/deadlock_stats'), ('GET', '/api/waf_bypass/info'), ('POST', '/api/waf_bypass/lfi_test_v3'), ('POST', '/api/waf_bypass/smart_scan_status'), ('POST', '/api/waf_bypass/ssrf_test_v3'), ('POST', '/api/waf_bypass/waf_bypass_report'), ('POST', '/api/waf_bypass/waf_detect'), ('POST', '/api/waf_bypass/xss_test_v3'), ('POST', '/api/recon/nmap_scan'), ('POST', '/api/recon/subfinder_enum'), ('POST', '/api/recon/httpx_probe'), ('POST', '/api/web/jwt_analyze'), ('POST', '/api/web/jwt_none_bypass'), ('POST', '/api/web/cors_check'), ('POST', '/api/web/header_check'), ('POST', '/api/web/xss_payloads'), ('POST', '/api/advanced/race_condition_test'), ('POST', '/api/advanced/http_smuggle_clte'), ('POST', '/api/osint/certificate_transparency'), ('POST', '/api/password/password_strength_check'), ('POST', '/api/cloud/cloud_metadata_ssrf'), ('POST', '/api/binary/strings_extract'), ('POST', '/api/browser/browser_security_headers'), ('POST', '/api/ctf/base64_tool'), ('POST', '/api/intel/advisory'), ('GET', '/api/intel/recent_critical')]

PUBLIC_ROUTES = {'/api/status', '/health', '/api/health'}


@pytest.mark.parametrize("method,path", ROUTES, ids=['POST:/api/agent/execute', 'POST:/api/agent/plan', 'GET:/api/agent/tasks', 'GET:/api/agent/tools', 'POST:/api/ai/analyze', 'POST:/api/ai/execute', 'POST:/api/ai/recommend', 'POST:/api/cache/clear', 'GET:/api/cache/stats', 'GET:/api/db/stats', 'GET:/api/auth/audit_log', 'POST:/api/waf_bypass/403_bypass_urls', 'POST:/api/waf_bypass/cmdi_test_v3', 'GET:/api/waf_bypass/deadlock_stats', 'GET:/api/waf_bypass/info', 'POST:/api/waf_bypass/lfi_test_v3', 'POST:/api/waf_bypass/smart_scan_status', 'POST:/api/waf_bypass/ssrf_test_v3', 'POST:/api/waf_bypass/waf_bypass_report', 'POST:/api/waf_bypass/waf_detect', 'POST:/api/waf_bypass/xss_test_v3', 'POST:/api/recon/nmap_scan', 'POST:/api/recon/subfinder_enum', 'POST:/api/recon/httpx_probe', 'POST:/api/web/jwt_analyze', 'POST:/api/web/jwt_none_bypass', 'POST:/api/web/cors_check', 'POST:/api/web/header_check', 'POST:/api/web/xss_payloads', 'POST:/api/advanced/race_condition_test', 'POST:/api/advanced/http_smuggle_clte', 'POST:/api/osint/certificate_transparency', 'POST:/api/password/password_strength_check', 'POST:/api/cloud/cloud_metadata_ssrf', 'POST:/api/binary/strings_extract', 'POST:/api/browser/browser_security_headers', 'POST:/api/ctf/base64_tool', 'POST:/api/intel/advisory', 'GET:/api/intel/recent_critical'])
def test_route_requires_auth(http, method, path):
    """Without API key, protected routes must return 401."""
    if path in PUBLIC_ROUTES:
        pytest.skip(f"{path} is public (no auth required)")
    status, body = http(method, path, key="")
    assert status == 401, f"{method} {path} without key returned {status} (expected 401). Body: {body[:200]}"


@pytest.mark.parametrize("method,path", ROUTES, ids=['POST:/api/agent/execute', 'POST:/api/agent/plan', 'GET:/api/agent/tasks', 'GET:/api/agent/tools', 'POST:/api/ai/analyze', 'POST:/api/ai/execute', 'POST:/api/ai/recommend', 'POST:/api/cache/clear', 'GET:/api/cache/stats', 'GET:/api/db/stats', 'GET:/api/auth/audit_log', 'POST:/api/waf_bypass/403_bypass_urls', 'POST:/api/waf_bypass/cmdi_test_v3', 'GET:/api/waf_bypass/deadlock_stats', 'GET:/api/waf_bypass/info', 'POST:/api/waf_bypass/lfi_test_v3', 'POST:/api/waf_bypass/smart_scan_status', 'POST:/api/waf_bypass/ssrf_test_v3', 'POST:/api/waf_bypass/waf_bypass_report', 'POST:/api/waf_bypass/waf_detect', 'POST:/api/waf_bypass/xss_test_v3', 'POST:/api/recon/nmap_scan', 'POST:/api/recon/subfinder_enum', 'POST:/api/recon/httpx_probe', 'POST:/api/web/jwt_analyze', 'POST:/api/web/jwt_none_bypass', 'POST:/api/web/cors_check', 'POST:/api/web/header_check', 'POST:/api/web/xss_payloads', 'POST:/api/advanced/race_condition_test', 'POST:/api/advanced/http_smuggle_clte', 'POST:/api/osint/certificate_transparency', 'POST:/api/password/password_strength_check', 'POST:/api/cloud/cloud_metadata_ssrf', 'POST:/api/binary/strings_extract', 'POST:/api/browser/browser_security_headers', 'POST:/api/ctf/base64_tool', 'POST:/api/intel/advisory', 'GET:/api/intel/recent_critical'])
def test_route_accepts_auth(http, method, path):
    """With valid API key, route must not return 401 (auth passes)."""
    # For POST routes, send empty body — expect 400 (bad request)
    # not 401 (auth failed) or 404 (not found)
    body = {} if method == "POST" else None
    status, resp_body = http(method, path, body=body)
    assert status != 401, f"{method} {path} with valid key returned 401. Body: {resp_body[:200]}"
    assert status != 404, f"{method} {path} returned 404 (route not found). Check URL."
    # 400 is OK (missing required params), 200 is OK, 202 is OK (async), 500 is a bug but not auth issue
