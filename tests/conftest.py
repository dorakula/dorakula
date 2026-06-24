"""DORAKULA test fixtures.

Assumes dorakula server is running at http://127.0.0.1:9093.
API key is extracted from /tmp/dorakula.log (printed at startup)
or from DORAKULA_API_KEY env var.
"""
import os, re, json, urllib.request, urllib.error
import pytest

BASE_URL = "http://127.0.0.1:9093"


def _extract_api_key():
    """Extract API key from startup log or env."""
    key = os.environ.get("DORAKULA_API_KEY", "")
    if key:
        return key
    log_path = "/tmp/dorakula.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            for line in f:
                m = re.match(r"\s*\[SECURITY\]\s+([A-Za-z0-9_-]{32,})", line)
                if m:
                    return m.group(1)
    pytest.skip("No API key found in DORAKULA_API_KEY env or /tmp/dorakula.log")


@pytest.fixture(scope="session")
def api_key():
    return _extract_api_key()


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture
def http(base_url, api_key):
    """HTTP helper. Usage: http("GET", "/api/health") or http("POST", "/path", body)."""
    def _call(method, path, body=None, key=None, timeout=15):
        url = base_url + path
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if key is None:
            key = api_key
        if key:
            headers["X-API-Key"] = key
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:
            return 0, f"{type(e).__name__}: {e}"
    return _call
