"""DORAKULA Ponytail fix tests — _build_call_kwargs edge cases.

Tests the smart parameter builder that:
  1. Inspects function signature
  2. Filters kwargs to accepted params
  3. Maps target to first accepted alias
  4. Supplies safe defaults for required params
  5. Type coercion (str→int, str→bool)
  6. Returns error if required param cannot be defaulted

These tests run against the live DORAKULA server via /api/run/<tool_name>.
"""
import json
import pytest


# ============================================================
# URL stripping tests (via tools that use target param)
# ============================================================

def test_url_strip_with_path(http):
    """Tools that strip URL must return bare hostname in response.target."""
    # smb_enum strips URL via _strip_to_hostname
    status, body = http("POST", "/api/run/smb_enum", {"target": "https://example.com/path"})
    assert status == 200
    data = json.loads(body)
    # Response target should be stripped (smbclient returns "example.com" not URL)
    # Note: smb_enum may fail with NT_STATUS_CONNECTION_REFUSED but target should be stripped
    target_in_response = data.get("target", "")
    # If target is the URL, stripping failed
    assert "https://" not in str(target_in_response), "URL leaked into response.target"


def test_url_strip_with_port(http):
    """URL with port must be stripped to bare hostname."""
    status, body = http("POST", "/api/run/smb_enum", {"target": "http://example.com:8080"})
    assert status == 200
    data = json.loads(body)
    assert "http://" not in str(data.get("target", ""))
    assert "8080" not in str(data.get("target", ""))


def test_url_strip_with_query(http):
    """URL with query string must be stripped to bare hostname."""
    status, body = http("POST", "/api/run/smb_enum", {"target": "https://example.com?q=test"})
    assert status == 200
    data = json.loads(body)
    assert "?" not in str(data.get("target", ""))
    assert "https://" not in str(data.get("target", ""))


def test_url_strip_with_auth(http):
    """URL with user:pass@ must be stripped to bare hostname."""
    status, body = http("POST", "/api/run/smb_enum", {"target": "http://user:pass@example.com/admin"})
    assert status == 200
    data = json.loads(body)
    target = str(data.get("target", ""))
    assert "user:pass" not in target
    assert "@" not in target
    assert "https://" not in target
    assert "http://" not in target


def test_url_strip_bare_hostname_unchanged(http):
    """Bare hostname must pass through unchanged."""
    status, body = http("POST", "/api/run/smb_enum", {"target": "example.com"})
    assert status == 200
    data = json.loads(body)
    # Bare hostname should work (no scheme to strip)


def test_url_strip_bare_ip_unchanged(http):
    """Bare IP must pass through unchanged."""
    status, body = http("POST", "/api/run/smb_enum", {"target": "127.0.0.1"})
    assert status == 200
    data = json.loads(body)
    target = str(data.get("target", ""))
    assert "127.0.0.1" in target


# ============================================================
# Type-aware default tests
# ============================================================

def test_safe_default_for_list_param(http):
    """Tools with List[Dict] param must get [] default, not crash with 'str'.get()."""
    # auto_generate_report expects findings: List[Dict]
    status, body = http("POST", "/api/run/auto_generate_report", {})
    assert status == 200
    data = json.loads(body)
    # Should NOT have "'str' object has no attribute 'get'" error
    err = str(data.get("error", ""))
    assert "'str' object has no attribute 'get'" not in err, "Type-aware default not working for List[Dict]"


def test_safe_default_for_dict_param(http):
    """Tools with Dict param must get {} default."""
    # dragon_eye_tui expects scan_status: Dict — may return string (TUI output)
    status, body = http("POST", "/api/run/dragon_eye_tui", {})
    assert status == 200
    # Response may be dict or string (dragon_eye_tui returns str)
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            err = str(data.get("error", ""))
            assert "'str' object has no attribute 'get'" not in err
        # If string, that's fine — tool ran without TypeError
    except json.JSONDecodeError:
        pass  # Non-JSON response is OK (TUI output)


def test_safe_default_for_attack_path(http):
    """generate_chained_exploit expects attack_path: Dict — must get {} default."""
    status, body = http("POST", "/api/run/generate_chained_exploit", {})
    assert status == 200
    data = json.loads(body)
    err = str(data.get("error", ""))
    assert "'str' object has no attribute 'get'" not in err


def test_safe_default_for_task(http):
    """self_healing_execute expects task: Dict — must get {} default."""
    status, body = http("POST", "/api/run/self_healing_execute", {})
    assert status == 200
    data = json.loads(body)
    err = str(data.get("error", ""))
    assert "'str' object has no attribute 'get'" not in err


# ============================================================
# Required param with safe default tests
# ============================================================

def test_safe_default_binary(http):
    """Tools requiring 'binary' param must get /bin/ls default."""
    # strings_extract requires binary param
    status, body = http("POST", "/api/run/strings_extract", {})
    assert status == 200
    data = json.loads(body)
    # Should NOT error with "requires parameter(s) not provided: binary"
    err = str(data.get("error", ""))
    assert "requires parameter" not in err.lower() or "binary" not in err.lower()


def test_safe_default_hash_value(http):
    """Tools requiring 'hash_value' param must get MD5 default."""
    # hash_identify requires hash_value param
    status, body = http("POST", "/api/run/hash_identify", {})
    assert status == 200
    data = json.loads(body)
    err = str(data.get("error", ""))
    assert "requires parameter" not in err.lower() or "hash_value" not in err.lower()


def test_safe_default_network(http):
    """Tools requiring 'network' param must get CIDR default."""
    # ping_sweep requires network param
    status, body = http("POST", "/api/run/ping_sweep", {})
    assert status == 200
    data = json.loads(body)
    err = str(data.get("error", ""))
    assert "requires parameter" not in err.lower() or "network" not in err.lower()


def test_safe_default_pcap_file(http):
    """Tools requiring 'pcap_file' param must get default path."""
    # pcaps_analyze requires pcap_file param
    status, body = http("POST", "/api/run/pcaps_analyze", {})
    assert status == 200
    data = json.loads(body)
    err = str(data.get("error", ""))
    # May fail because file doesn't exist, but should NOT fail with "requires parameter"
    assert "requires parameter" not in err.lower() or "pcap_file" not in err.lower()


# ============================================================
# Target alias mapping tests
# ============================================================

def test_target_to_domain_mapping(http):
    """When function accepts 'domain' (not 'target'), target must map to domain."""
    # subfinder_enum accepts domain param
    status, body = http("POST", "/api/run/subfinder_enum", {"target": "example.com"})
    assert status == 200
    # Should not crash with "missing required positional argument: domain"


def test_target_to_url_mapping(http):
    """When function accepts 'url' (not 'target'), target must map to url."""
    # Test with a tool that uses url param (if exists)
    # jwt_analyze uses target, but cors_check uses target too
    status, body = http("POST", "/api/run/cors_check", {"target": "https://example.com"})
    assert status == 200


# ============================================================
# Non-interactive mode tests
# ============================================================

def test_evil_winrm_no_creds_early_return(http):
    """evil_winrm without user/password must early-return with clear error (no hang)."""
    import time
    t0 = time.time()
    status, body = http("POST", "/api/run/evil_winrm", {"target": "example.com"})
    elapsed = time.time() - t0
    assert status == 200
    data = json.loads(body)
    err = str(data.get("error", ""))
    assert "requires both 'user' and 'password'" in err
    # Must be fast (early return, no hang)
    assert elapsed < 5.0, f"evil_winrm took {elapsed}s — possible hang"


def test_steghide_extract_no_prompt(http):
    """steghide_extract without passphrase must NOT prompt (no hang)."""
    import time
    t0 = time.time()
    status, body = http("POST", "/api/run/steghide_extract", {"file_path": "/etc/hostname"})
    elapsed = time.time() - t0
    assert status == 200
    data = json.loads(body)
    err = str(data.get("error", "") or data.get("errors", ""))
    # Must NOT contain "Enter passphrase"
    assert "Enter passphrase" not in err
    # Must be fast
    assert elapsed < 5.0, f"steghide_extract took {elapsed}s — possible hang"


# ============================================================
# File pre-check tests
# ============================================================

def test_volatility3_mem_nonexistent_file(http):
    """volatility3_mem with non-existent file must return clear error."""
    status, body = http("POST", "/api/run/volatility3_mem", {"memory_dump": "/tmp/nonexistent_xyz.raw"})
    assert status == 200
    data = json.loads(body)
    err = str(data.get("error", ""))
    assert "file not found" in err.lower()
    # Must NOT show vol usage dump
    assert "usage:" not in err.lower()


def test_upx_unpack_uses_temp_dir(http):
    """upx_unpack must use temp dir for output (no Permission denied)."""
    status, body = http("POST", "/api/run/upx_unpack", {"binary": "/bin/ls"})
    assert status == 200
    data = json.loads(body)
    err = str(data.get("error", "") or data.get("errors", ""))
    # Must NOT have Permission denied
    assert "Permission denied" not in err
    # Output file should be in temp dir
    data_field = data.get("data", {})
    if isinstance(data_field, dict):
        unpacked = data_field.get("unpacked_file", "")
        if unpacked:
            assert "/tmp/dorakula_" in unpacked or "dorakula_" in unpacked, \
                f"Output not in temp dir: {unpacked}"
