<div align="center">

```
██████   ██████  ███████ ███   ██  █████      ██████  ██████   ██████   ██████
██   ██ ██    ██ ██      ████  ██ ██   ██     ██   ██ ██   ██ ██    ██ ██
██   ██ ██    ██ █████   ██ ██ ██ ███████     ██████  ██████  ██    ██ ██   ███
██   ██ ██    ██ ██      ██  ████ ██   ██     ██      ██   ██ ██    ██ ██    ██
██████   ██████  ███████ ██   ███ ██   ██     ██      ██   ██  ██████   ██████
```

# 🧛 DORAKULA v3.1.0

### The Night Stalker of Cyberspace

**Offensive Security MCP Platform** · **219 REST Routes** · **192 MCP Tools** · **Ollama Cloud AI** · **WAF Bypass Engine** · **7 Advanced Modules**

---

![Version](https://img.shields.io/badge/Version-3.1.0-crimson?style=for-the-badge&logo=python&logoColor=white)
![Tools](https://img.shields.io/badge/Security_Tools-192+-8B0000?style=for-the-badge&logo=shield&logoColor=white)
![AI](https://img.shields.io/badge/AI-Ollama_Cloud-4B0082?style=for-the-badge&logo=openai&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-Compatible-2F0743?style=for-the-badge&logo=data:image/svg+xml;base64,&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-1a1a1a?style=for-the-badge&logo=github&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali_Linux-2F0743?style=for-the-badge&logo=kalilinux&logoColor=white)

![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=flat-square&logo=flask&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-88_PASS-brightgreen?style=flat-square&logo=pytest&logoColor=white)
![Coverage](https://img.shields.io/badge/Coverage-70%25+-yellow?style=flat-square&logo=codecov&logoColor=white)
![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)

---

> ⚠️ **WARNING: This tool is for AUTHORIZED security testing only.**
> Unauthorized use against systems you don't own is illegal.
> DORAKULA doesn't forgive. Neither should you.

</div>

---

## 🦇 What is DORAKULA?

DORAKULA is not just another security scanner. It's a **full-spectrum offensive security platform** that hunts vulnerabilities like a predator in the night. With **219 REST endpoints**, **192 MCP tools**, and **AI-powered analysis** via Ollama Cloud, it covers everything from recon to exploitation to reporting — all from a single Python process.

### Why DORAKULA?

| Feature | Description |
|---------|-------------|
| 🧛 **Dual Interface** | REST API (Flask) + MCP SSE (Starlette) — same tools, two ways to access |
| 🤖 **AI-Powered** | 5-key Ollama rotation pool with auto-failover, 3-tier model system (quick/medium/heavy) |
| 🛡️ **WAF Bypass Engine** | AI-generated payload obfuscation, 9 encoding techniques, WAF fingerprinting |
| 🔒 **Security Hardened** | Rate limiting, audit logging, HMAC signatures, per-endpoint limits, fail-closed auth |
| 📊 **Full Observability** | Prometheus metrics, audit log query + stats, OpenAPI spec, Swagger UI |
| 🐳 **Docker Ready** | Dockerfile + docker-compose.yml, health checks, persistent volumes |
| 🧪 **Test Suite** | 88 pytest tests, GitHub Actions CI, pre-commit hooks, coverage reports |
| 📦 **7 Advanced Modules** | WAF Bypass AI, LLM Security, Cloud Auditor, GraphQL, Supply Chain, WebSocket Fuzzer, Auto-Reporter |

---

## 🩸 Quick Start

```bash
# Clone the repository
git clone https://github.com/dorakula/dorakula.git
cd dorakula

# Create virtual environment
python3 -m venv dorakula-env
source dorakula-env/bin/activate

# Install dependencies
pip install -r requirements.txt -r requirements.dev.txt

# Start the server (API key auto-generated if not set)
python dorakula_server.py

# Or with AI enabled (requires Ollama Cloud API keys in .env)
python dorakula_server.py --port 9092
```

### Server Endpoints

| Service | URL | Auth |
|---------|-----|------|
| REST API | `http://127.0.0.1:9093` | `X-API-Key` header |
| MCP SSE | `http://127.0.0.1:9092/sse` | Session-based |
| Swagger UI | `http://127.0.0.1:9093/api/docs` | None |
| OpenAPI Spec | `http://127.0.0.1:9093/api/openapi.json` | None |
| Prometheus Metrics | `http://127.0.0.1:9093/metrics` | None |
| Health Check | `http://127.0.0.1:9093/api/health` | None |

### Quick Test

```bash
# Get API key from server startup log
API_KEY="your-api-key-here"

# List available tools
curl -H "X-API-Key: $API_KEY" http://127.0.0.1:9093/api/agent/tools

# Analyze a JWT token
curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}' \
  http://127.0.0.1:9093/api/web/jwt_analyze

# Get AI-powered tool recommendation
curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","context":"web"}' \
  http://127.0.0.1:9093/api/ai/recommend
```

---

## 🔧 Tool Categories (219 Routes · 192 MCP Tools)

### 🎯 Reconnaissance & Scanning (25 routes)
`nmap_scan` · `masscan` · `rustscan` · `subfinder_enum` · `amass_enum` · `httpx_probe` · `whatweb_scan` · `dnsrecon` · `dnsenum` · `fierce_scan` · `gobuster_dns` · `enum4linux_scan` · `sslscan_tool` · `sslyze_scan` · `testssl_scan` · `theharvester` · `arjun_params` · `paramspider_crawl` · `ping_sweep` · `netbios_scan` · `smb_enum` · `nmap_stealth` · `nmap_udp` · `autorecon` · `traceroute_tool`

### 🌐 Web Application Security (40 routes)
`nuclei_scan` · `nikto_scan` · `sqlmap_scan` · `dalfox_xss` · `xss_scan` · `xss_payloads` · `cors_check` · `header_check` · `jwt_analyze` · `jwt_none_bypass` · `jwt_crack` · `lfi_test` · `lfi_wrapper_test` · `ssrf_test` · `ssrf_cloud_metadata` · `cmd_injection_test` · `cmd_blind_test` · `commix_test` · `nosqlmap_test` · `tplmap_test` · `open_redirect_test` · `cookie_security_check` · `content_type_fuzz` · `wafw00f_detect` · `gobuster_dir` · `feroxbuster_dir` · `ffuf_dir` · `dirsearch_scan` · `dirb_scan` · `katana_crawl` · `hakrawler_crawl` · `gau_urls` · `waybackurls` · `wpscan_enum` · `graphql_introspect` · `api_fuzz_rest` · `api_fuzz_graphql` · `api_test_bola` · `rest_api_fuzz` · `wfuzz_fuzz`

### 🧪 WAF Bypass Engine v2.5 (9 routes)
`waf_detect` · `403_bypass_urls` · `ssrf_test_v3` · `lfi_test_v3` · `xss_test_v3` · `cmdi_test_v3` · `waf_bypass_report` · `smart_scan_status` · `deadlock_stats`

### ⚡ Modern Attack Vectors (15 routes)
`race_condition_test` · `http_smuggle_clte` · `http_smuggle_tecl` · `request_smuggling` · `subdomain_takeover_scan` · `subdomain_takeover_check` · `supply_chain_audit_js` · `supply_chain_check_sri` · `prototype_pollution_test` · `websocket_test_unauth` · `idor_test` · `mass_assignment_test` · `cache_poisoning_test` · `csp_bypass_test` · `host_header_injection`

### 🤖 AI & LLM Security (2 routes) — *NEW in v3.1.0*
`llm_security/scan` · `llm_security/prompt_injection` — Tests prompt injection, jailbreak, data leakage, model DoS

### ☁️ Cloud Security (20 routes)
`aws_prowler` · `aws_pacu` · `aws_s3_enum` · `aws_bucket_check` · `azure_scanner` · `gcp_scanner` · `cloud_metadata_ssrf` · `kube_hunter` · `kube_bench` · `k8s_api_check` · `trivy_scan` · `checkov_scan` · `terrascan_scan` · `scout_suite` · `cloudmapper` · `docker_bench` · `serverless_scan` · `iam_enum` · `cloud_frontier` · `s3_bucket_misconfig`

### 🔍 OSINT (15 routes)
`shodan_search` · `censys_search` · `haveibeenpwned_check` · `hibp_breach_search` · `sherlock_hunt` · `spiderfoot_scan` · `social_analyzer` · `certificate_transparency` · `wayback_machine` · `git_dork` · `github_secret_scan` · `trufflehog_scan` · `subjack_check` · `aquatone_screenshot` · `reconng_module`

### 🔐 Password Cracking (12 routes)
`hydra_brute` · `john_crack` · `hashcat_crack` · `medusa_brute` · `patator_brute` · `evil_winrm` · `netexec_smb` · `netexec_ssh` · `hash_identify` · `hash_crack_autodetect` · `password_strength_check` · `brute_force_custom`

### 🧬 Binary Analysis (15 routes)
`ghidra_analyze` · `radare2_analyze` · `angr_analyze` · `gdb_debug` · `pwntools_exploit` · `msfvenom_generate` · `binwalk_extract` · `strings_extract` · `checksec_tool` · `ropgadget_find` · `ropper_find` · `objdump_analyze` · `readelf_analyze` · `upx_unpack` · `volatility_analyze`

### 🖥️ Browser Automation (10 routes)
`browser_crawl` · `browser_screenshot` · `browser_dom_analyze` · `browser_form_detect` · `browser_js_execute` · `browser_network_monitor` · `browser_security_headers` · `browser_cookie_analyze` · `browser_performance` · `browser_proxy_check`

### 🏁 CTF Toolkit (15 routes)
`base64_tool` · `binwalk_firmware` · `cipher_identify` · `cyberchef_decode` · `exiftool_read` · `foremost_recover` · `frequency_analysis` · `hash_crack_ctf` · `memory_strings` · `pcaps_analyze` · `photorec_recover` · `registry_parse` · `steghide_extract` · `volatility3_mem` · `zsteg_detect`

### 🧠 AI Endpoints (3 routes)
`ai/analyze` · `ai/recommend` · `ai/execute` — Ollama Cloud integration with 3-tier model system

### 📊 Observability & Admin (12 routes)
`health` · `status` · `metrics` · `openapi.json` · `docs` · `auth/audit_log` · `auth/audit_log/stats` · `cache/stats` · `cache/clear` · `db/stats` · `reports/auto/generate` · `reports/auto/validate`

### 🆕 Advanced Modules (15 routes) — *ROADMAP Implementation*
`waf_bypass_ai/obfuscate` · `waf_bypass_ai/fingerprint` · `cloud_auditor/scan` · `cloud_auditor/s3_check` · `graphql/scan` · `graphql/introspect` · `supply_chain/analyze` · `supply_chain/typosquat` · `ws_fuzzer/scan` · `ws_fuzzer/injection` · `llm_security/scan` · `llm_security/prompt_injection` · `reports/auto/generate` · `reports/auto/validate`

---

## 🧠 Ollama Cloud AI

DORAKULA integrates with Ollama Cloud for AI-powered vulnerability analysis with a token-efficient 3-tier model system:

| Tier | Default Model | Max Tokens | Use Case |
|------|---------------|------------|----------|
| **Quick** | `ministral-3:8b` | 150 | Tool recommendations, quick triage |
| **Medium** | `gemma3:27b` | 300 | Vulnerability analysis, priority ranking |
| **Heavy** | `gemma4:31b` | 500 | Exploit chain generation, deep analysis |

### Key Rotation Pool
DORAKULA supports up to 10 Ollama API keys with automatic rotation on quota/auth errors:

```bash
# .env file
OLLAMA_API_KEY_1=your-first-key
OLLAMA_API_KEY_2=your-second-key
OLLAMA_API_KEY_3=your-third-key
# ... up to 10 keys
```

When a key returns 401/429/quota error, DORAKULA automatically rotates to the next key and retries.

---

## 🔒 Security Features

| Layer | Implementation | Status |
|-------|---------------|--------|
| **API Key Auth** | `secrets.compare_digest` (constant-time) | ✅ Active |
| **Fail-Closed** | No key = 401, random key generated if not configured | ✅ Active |
| **Rate Limiting** | 100 req/60s per client IP (global) | ✅ Active |
| **Per-Endpoint Limit** | `_rate_limit(per_minute=N)` decorator | ✅ Available |
| **Audit Logging** | SQLite `audit.db`, all auth events recorded | ✅ Active |
| **Audit Log Query** | `/api/auth/audit_log` (paginated + filtered) | ✅ Active |
| **Audit Log Stats** | `/api/auth/audit_log/stats` (aggregates) | ✅ Active |
| **HMAC Signatures** | Optional `X-Dorakula-Signature` verification | ✅ Active |
| **Rate Limit Headers** | `Retry-After`, `X-RateLimit-Remaining` | ✅ Active |
| **Ollama Key Rotation** | 5-key pool with auto-failover | ✅ Active |

---

## 📊 Observability

### Prometheus Metrics (`/metrics`)
```
dorakula_requests_total          # counter
dorakula_auth_failures_total     # counter
dorakula_auth_success_total      # counter
dorakula_rate_limit_hits_total   # counter
dorakula_ai_calls_total          # counter
dorakula_tool_runs_total         # counter
dorakula_errors_500_total        # counter
dorakula_uptime_seconds          # gauge
dorakula_tools_registered        # gauge (192)
dorakula_cache_size              # gauge
dorakula_ai_available            # gauge (0 or 1)
```

### API Documentation
- **Swagger UI**: `http://localhost:9093/api/docs`
- **OpenAPI Spec**: `http://localhost:9093/api/openapi.json` (219 paths auto-generated)

---

## 🐳 Docker Deployment

```bash
# Quick start with docker-compose
docker-compose up -d

# Or build manually
docker build -t dorakula .
docker run -p 9092:9092 -p 9093:9093 \
  -e DORAKULA_API_KEY=your-strong-key \
  -e OLLAMA_API_KEY_1=your-ollama-key \
  dorakula
```

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -r requirements.txt -r requirements.dev.txt

# Start server (required for tests)
python dorakula_server.py --no-ai &

# Run all tests (88 tests, ~16s)
pytest tests/ -v -k "not rate_limit"

# Run with coverage
pytest tests/ -v --cov --cov-report=html

# Run specific test
pytest tests/test_smoke.py::test_jwt_analyze -v
```

---

## 📁 Project Structure

```
dorakula/
├── dorakula_server.py          # Main server (10K+ lines, all-in-one)
├── core/                       # Core infrastructure
│   ├── auth.py                 # AuthManager (aspirational reference)
│   ├── audit_log.py            # AuditLogger (SQLite)
│   ├── config.py               # Configuration helpers
│   └── sandbox.py              # SecureSandboxExecutor (aspirational)
├── agents/                     # AI agent modules
│   ├── ai_router.py            # Ollama Cloud router (5-key rotation)
│   ├── xss_scanner.py          # XSS scanning
│   ├── jwt_analyzer.py         # JWT security analysis
│   ├── graphql_specialist.py   # GraphQL security (NEW)
│   ├── auto_reporter.py        # Auto-reporting (NEW)
│   └── ...
├── advanced/                   # Advanced attack modules
│   ├── waf_bypass_ai.py        # AI-powered WAF bypass (NEW)
│   ├── llm_security.py         # LLM security testing (NEW)
│   ├── cloud_auditor.py        # Cloud audit (NEW)
│   ├── supply_chain_analyzer.py # Supply chain analysis (NEW)
│   ├── websocket_fuzzer.py     # WebSocket fuzzing (NEW)
│   └── ...
├── tests/                      # Pytest suite (88 tests)
│   ├── conftest.py             # Fixtures
│   ├── test_routes.py          # Parametrized auth tests
│   └── test_smoke.py           # Functional smoke tests
├── .github/                    # GitHub config
│   ├── workflows/ci.yml        # CI pipeline
│   └── ISSUE_TEMPLATE/         # Bug + feature templates
├── .githooks/                  # Pre-commit hook
├── Dockerfile                  # Docker image
├── docker-compose.yml          # Docker Compose
├── requirements.txt            # Production deps (14 packages)
├── requirements.dev.txt        # Dev deps (pytest, pytest-cov)
├── pytest.ini                  # Pytest config
├── .coveragerc                 # Coverage config
├── ARCHITECTURE.md             # Full architecture docs
├── CONTRIBUTING.md             # Contribution guide
├── ROADMAP_MODUL_ADVANCED.md   # Advanced module roadmap
└── README.md                   # This file
```

---

## 🗺️ Roadmap

All 7 modules from `ROADMAP_MODUL_ADVANCED.md` have been implemented:

- [x] **WAF Bypass AI** — AI payload obfuscation + WAF fingerprinting
- [x] **LLM Security** — Prompt injection, jailbreak, data leakage testing
- [x] **Cloud Auditor** — AWS/GCP/Azure metadata, S3, K8s checks
- [x] **GraphQL Specialist** — Introspection, depth limit, batch attacks
- [x] **Supply Chain Analyzer** — Typosquatting, CI/CD injection, dependency confusion
- [x] **WebSocket Fuzzer** — Handshake fuzzing, message injection, connection flood
- [x] **Auto-Reporter** — Markdown/JSON reports, severity calibration, PoC validation

---

## ⚖️ Legal & Ethics

<div align="center">

**⚠️ DORAKULA is for AUTHORIZED security testing only. ⚠️**

</div>

**Authorized Use:**
- ✅ Bug bounty programs with explicit authorization
- ✅ Penetration testing with signed scope agreements
- ✅ Security research on systems you own
- ✅ CTF competitions and educational purposes

**Forbidden:**
- ❌ Testing systems without explicit permission
- ❌ Exploiting vulnerabilities for personal gain
- ❌ Using this tool for illegal activities

---

## 📜 License

MIT License — see [LICENSE](LICENSE) file for details.

---

<div align="center">

**🧛 DORAKULA v3.1.0 — The Night Stalker of Cyberspace**

*Built with blood, sweat, and Python 3.13*

[Report Bug](https://github.com/dorakula/dorakula/issues) · [Request Feature](https://github.com/dorakula/dorakula/issues) · [Architecture](ARCHITECTURE.md) · [Contributing](CONTRIBUTING.md)

</div>
