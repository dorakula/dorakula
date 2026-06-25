# DORAKULA v3.1.0 — Architecture

## Overview

DORAKULA is a dual-interface offensive security platform:
- **REST API** (Flask, port 9093) — 198 routes for direct curl/script access
- **MCP SSE** (Starlette + uvicorn, port 9092) — 192 tools for AI agent integration

Both interfaces share the same `ToolImplementations` instance, so a tool
invoked via REST and via MCP produces identical results.

## Process Architecture

```
                    ┌─────────────────────────────────┐
                    │     dorakula_server.py          │
                    │     (single Python process)     │
                    ├─────────────────────────────────┤
                    │                                 │
  curl/HTTP ──────► │  Flask app (port 9093)          │
                    │    └─ _api_key_required         │
                    │       (rate limit + audit +     │
                    │        metrics + headers)       │
                    │                                 │
  MCP client ─────► │  MCP SSE (port 9092)            │
  (Claude/Cursor)   │    └─ FastMCP server            │
                    │       (192 tools registered)    │
                    │                                 │
                    │  Shared:                        │
                    │    ├─ ToolImplementations        │
                    │    │   (192 security tools)     │
                    │    ├─ AIRouter                   │
                    │    │   (Ollama Cloud, 5-key     │
                    │    │    rotation pool)          │
                    │    ├─ SandboxExecutor            │
                    │    │   (subprocess + timeout)   │
                    │    ├─ LRUCache (256 entries)    │
                    │    ├─ AuditLogger (SQLite)      │
                    │    └─ _APIKeyRateLimiter         │
                    │       (100 req/60s/client)      │
                    └─────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
              ┌─────▼─────┐     ┌──────▼──────┐
              │ audit.db  │     │ Ollama Cloud│
              │ (SQLite)  │     │ (35 models) │
              └───────────┘     └─────────────┘
```

## Request Flow (REST API)

1. Client sends HTTP request with `X-API-Key` header
2. `_api_key_required` decorator:
   - Extracts client_id from `X-Forwarded-For` or `remote_addr`
   - Increments `requests_total` metric
   - Checks rate limit (100 req/60s per client_id)
   - If over limit → 429 + `Retry-After` + `X-RateLimit-*` headers + audit log
   - Validates API key via `secrets.compare_digest` (constant-time)
   - If invalid → 401 + `X-RateLimit-Remaining` + audit log
   - If valid → increment `auth_success`, call handler, inject `X-RateLimit-Remaining` on response

## Request Flow (MCP)

1. Client opens SSE connection to `/sse`
2. Server sends `event: endpoint` with `session_id`
3. Client sends JSON-RPC `initialize` to `/messages?session_id=...`
   - Note: Starlette returns 307 redirect to `/messages/?session_id=...`
   - MCP clients (mcp-cli, Cursor, Claude Desktop) follow redirects automatically
4. Server responds via SSE event stream with initialize result
5. Client sends `tools/list` → server returns 192 tools with inputSchema
6. Client sends `tools/call` with tool name + arguments → server executes + returns result via SSE

## Security Layers

| Layer | Implementation | Session Added |
|-------|---------------|---------------|
| API key auth | `secrets.compare_digest` (constant-time) | S0 (original) |
| Fail-closed | No key = 401, no open mode | S2A (random key if not set) |
| Rate limiting | 100 req/60s per client IP | S3 |
| Audit logging | SQLite `audit.db`, all auth events | S3 |
| Audit log query | `/api/auth/audit_log` (paginated + filter) | S4L |
| Audit log stats | `/api/auth/audit_log/stats` (aggregates) | S7Q |
| Rate limit headers | `Retry-After`, `X-RateLimit-Remaining` | S7U+V |
| Ollama key rotation | 5-key pool, auto-rotate on 401/429 | S3F + S4K |

## Observability

| Endpoint | Purpose | Auth |
|----------|---------|------|
| `/api/health` | Liveness check, version, tool count | None |
| `/api/status` | Detailed server status | None |
| `/metrics` | Prometheus-format metrics | None |
| `/api/auth/audit_log` | Query auth events | API key |
| `/api/auth/audit_log/stats` | Aggregate auth statistics | API key |
| `/api/cache/stats` | Cache hit/miss stats | API key |
| `/api/db/stats` | SQLite DB stats | API key |

## Metrics (Prometheus format)

```
dorakula_requests_total          # counter
dorakula_auth_failures_total     # counter
dorakula_auth_success_total      # counter
dorakula_rate_limit_hits_total   # counter
dorakula_ai_calls_total          # counter
dorakula_tool_runs_total         # counter
dorakula_errors_500_total        # counter
dorakula_uptime_seconds          # gauge
dorakula_tools_registered        # gauge
dorakula_cache_size              # gauge
dorakula_ai_available            # gauge (0 or 1)
```

## Tool Categories (192 MCP tools, 198 REST routes)

| Category | Routes | Tools |
|----------|--------|-------|
| Reconnaissance | 25 | nmap, subfinder, masscan, httpx, amass, dnsrecon |
| Web Application Security | 40 | nuclei, nikto, sqlmap, jwt_analyze, cors_check |
| WAF Bypass Engine | 9 | waf_detect, 403_bypass, v3 test variants |
| Modern Attack Vectors | 15 | race_condition, http_smuggling, subdomain_takeover |
| OSINT | 15 | shodan, censys, hibp, sherlock, spiderfoot |
| Password Cracking | 12 | hashcat, john, hydra, evil_winrm, netexec |
| Cloud Security | 20 | prowler, scout_suite, kube_hunter, trivy |
| Binary Analysis | 15 | angr, ghidra, radare2, gdb, pwntools |
| Browser Automation | 10 | crawl, screenshot, dom_analyze |
| CTF Toolkit | 15 | steghide, binwalk, volatility, cyberchef |
| AI Agent | 5 | plan, execute, tools, tasks |
| AI | 3 | analyze, recommend, execute |
| Cache/DB/Auth/Intel | 8 | stats, query, stats, advisory |

## Configuration

Environment variables (loaded via shell `set -a; . ./.env`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `DORAKULA_API_KEY` | (random) | API key for auth (printed at startup if not set) |
| `OLLAMA_API_KEY` | (empty) | Primary Ollama Cloud API key |
| `OLLAMA_API_KEY_1..10` | (empty) | Rotation pool keys |
| `DORAKULA_PORT` | 9092 | MCP SSE port (REST = port+1) |

## Test Suite

```bash
# Install dev dependencies
pip install -r requirements.txt -r requirements.dev.txt

# Run tests (server must be running on 127.0.0.1:9093)
pytest tests/ -v

# Run specific test
pytest tests/test_smoke.py::test_jwt_analyze -v

# Skip rate-limit-consuming tests
pytest tests/ -k "not rate_limit"
```

88 tests covering:
- 39 endpoints × 2 (auth required + auth accepted) = 78 parametrized
- 12 functional smoke tests (health, jwt, audit_log, rate_limit, etc.)

## File Structure

```
dorakula/
├── dorakula_server.py      # Main server (10K+ lines, all-in-one)
├── core/
│   ├── auth.py             # AuthManager (DEAD CODE — aspirational reference)
│   ├── sandbox.py          # SecureSandboxExecutor (DEAD CODE — not used)
│   ├── audit_log.py        # AuditLogger (used)
│   ├── config.py           # Configuration helpers
│   └── ...
├── agents/                 # AI agent modules (ai_router, xss_scanner, etc.)
├── advanced/               # Modern attack vectors (race_condition, smuggling, etc.)
├── tests/                  # pytest suite (88 tests)
│   ├── conftest.py         # Fixtures (API key, HTTP helper)
│   ├── test_routes.py      # Parametrized auth tests
│   └── test_smoke.py       # Functional smoke tests
├── requirements.txt        # Production dependencies (14 packages)
├── requirements.dev.txt    # Development dependencies (pytest, pytest-cov)
├── pytest.ini              # pytest configuration
├── .env.example            # Environment template
├── README.md               # User documentation (198 routes documented)
├── ARCHITECTURE.md         # This file
└── SECURITY_REPORT.py      # Demo script (claims v6.0 IRON FORTRESS, partially true)
```

## Known Limitations

1. **Single-process**: Flask dev server with `threaded=True`. For production,
   use gunicorn with multiple workers + Redis for rate limiter state.
2. **In-memory rate limiter**: Resets on restart. Multiple workers would each
   have their own counter.
3. **In-memory metrics**: Same limitation. Use prometheus_client + Redis for
   multi-worker setups.
4. **No HMAC signature verification**: AuthManager in core/auth.py has it,
   but the production decorator only checks API key. Adding HMAC requires
   client-side changes too.
5. **Dead code**: `core/auth.py` (AuthManager) and `core/sandbox.py`
   (SecureSandboxExecutor) are not imported by the production code path.
   They serve as aspirational references for future enhancements.


---

## Sovereign Intelligence Module (v3.1.0+)

DORAKULA includes a Sovereign Intelligence Module that replaces foreign
API-dependent tools (Shodan, Censys, HIBP) with 100% local equivalents.

### Architecture

```
┌────────────────────────────────────────────────────────────┐
│  SovereignIntel (advanced/sovereign_intel.py)              │
│                                                             │
│  sovereign_shodan ──┐    ┌── sovereign_censys               │
│  (nmap + cache)     │    │   (nmap -sV + cache)             │
│                     ▼    ▼                                  │
│            ┌─────────────────────┐                          │
│            │ SQLite scan_results │                          │
│            │ + FTS5 index        │                          │
│            └─────────────────────┘                          │
│                                                             │
│  sovereign_hibp ──┐    ┌── sovereign_hibp_import            │
│  (offline SHA-1)  │    │   (one-time data loader)           │
│                   ▼    ▼                                     │
│  ┌─────────────────────┐    ┌─────────────────────────┐    │
│  │ hibp_passwords      │    │ hibp_breaches           │    │
│  │ + idx_hibp_prefix   │    │                         │    │
│  └─────────────────────┘    └─────────────────────────┘    │
│                                                             │
│  DB: /tmp/dorakula_sovereign.db                             │
└────────────────────────────────────────────────────────────┘
```

### Tool Replacement Mapping

| Original (Foreign API) | Sovereign Replacement | API Key Eliminated |
|------------------------|----------------------|-------------------|
| shodan_search | sovereign_shodan | SHODAN_API_KEY |
| censys_search | sovereign_censys | CENSYS_API_ID/SECRET |
| haveibeenpwned_check | sovereign_hibp (email) | HIBP_API_KEY |
| hibp_breach_search | sovereign_hibp (email) | HIBP_API_KEY |
| (new) | sovereign_hibp (password) | HIBP password API |
| (new) | sovereign_hibp_import | N/A |
| (new) | sovereign_stats | N/A |

See `SOVEREIGN_DOCTRINE.md` for full compliance documentation.

