<div align="center">

# DORAKULA v3.1 Cloud
### Offensive Security Platform | 167+ Tools | Ollama Cloud AI | Sovereign Mode

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Offensive-red.svg)](https://github.com/dorakula/dorakula)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://github.com/dorakula/dorakula)
[![Version](https://img.shields.io/badge/Version-3.1_Cloud-orange.svg)](https://github.com/dorakula/dorakula)
[![Tools](https://img.shields.io/badge/Security%20Tools-167%2B-brightgreen.svg)](https://github.com/dorakula/dorakula)
[![AI](https://img.shields.io/badge/AI-Ollama%20Cloud-blueviolet.svg)](https://ollama.com)
[![Sovereign](https://img.shields.io/badge/Mode-Sovereign-crimson.svg)](https://github.com/dorakula/dorakula)

**Advanced offensive security platform with 167+ tools, Ollama Cloud AI integration, WAF Bypass Engine, and Sovereign Mode for national cyber defense**

[🚀 Quick Start](#quick-start) • [🛠️ Tools](#tools-167) • [🤖 AI Integration](#ollama-cloud-ai) • [📡 API Reference](#api-reference) • [🛡️ Sovereign Mode](#sovereign-mode)

</div>

---

## What is DORAKULA?

DORAKULA is a purpose-built offensive security platform designed for authorized penetration testing, bug bounty hunting, and national cyber defense. Unlike general security tools, DORAKULA provides a unified MCP + REST API interface with 167+ security tools, AI-powered analysis via Ollama Cloud, WAF Bypass Engine, and Deadlock Recovery.

### Key Highlights
- **167+ Security Tools** across 10 vulnerability categories
- **Ollama Cloud AI** — Token-efficient 3-tier model system (quick/medium/heavy)
- **WAF Bypass Engine** — Automatic WAF detection and evasion (SafeLine, Cloudflare, etc.)
- **Deadlock Recovery** — Automatic retry with alternate techniques on scan failures
- **MCP + REST API** — Dual interface for AI agents and direct curl access
- **Auto-Fallback AI** — Automatic retry with free models when paid models fail
- **Sovereign Mode** — National-grade cyber defense capabilities
- **6 DORAKULA-Exclusive Modules** not found in any other framework

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/dorakula/dorakula.git
cd dorakula

# 2. Create virtual environment
python3 -m venv dorakula-env
source dorakula-env/bin/activate

# 3. Install dependencies
pip3 install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your Ollama Cloud API key

# 5. Start the server
python3 dorakula_server.py --ollama-api-key YOUR_KEY
```

---

## Tools (167+)

### Reconnaissance & Scanning (20+ Tools)
| Tool | Description |
|------|-------------|
| `nmap_scan` | Network port scanning with service detection |
| `nuclei_scan` | Vulnerability scanning with custom templates |
| `subfinder_enum` | Subdomain discovery and enumeration |
| `httpx_probe` | HTTP service probing and technology detection |
| `feroxbuster_scan` | Recursive directory fuzzing |
| `whatweb_scan` | Technology fingerprinting |
| `arjun_params` | Hidden HTTP parameter discovery |
| `paramspider_crawl` | Parameter mining and crawling |
| `testssl_scan` | Deep SSL/TLS analysis |
| `cors_check` | CORS misconfiguration detection |

### Bug Bounty Core (30+ Tools)
| Tool | Description |
|------|-------------|
| `xss_scan` | Advanced XSS scanning with Dalfox + AI |
| `ssrf_test` | SSRF vulnerability testing |
| `lfi_test` | Local File Inclusion testing |
| `cmd_injection_test` | Command injection testing |
| `jwt_analyze` | JWT token security analysis |
| `jwt_none_bypass` | JWT none algorithm bypass |
| `jwt_algorithm_confusion` | JWT RS256→HS256 confusion attack |
| `jwt_crack` | JWT secret brute forcing |
| `jwt_forge` | AI-assisted JWT token forging |

### API Security (10+ Tools)
| Tool | Description |
|------|-------------|
| `api_fuzz_rest` | REST API endpoint fuzzing |
| `api_fuzz_graphql` | GraphQL introspection and abuse |
| `api_fuzz_openapi` | OpenAPI spec parsing and fuzzing |
| `api_test_bola` | BOLA/IDOR testing |
| `api_test_mass_assignment` | Mass assignment vulnerability testing |

### Modern Attack Vectors — DORAKULA Exclusive (20+ Tools)
| Tool | Description |
|------|-------------|
| `race_condition_test` | Race condition vulnerability detection |
| `http_smuggle_clte` | CL.TE HTTP request smuggling |
| `http_smuggle_tecl` | TE.CL HTTP request smuggling |
| `subdomain_takeover_scan` | Full subdomain takeover scan |
| `supply_chain_audit_js` | JavaScript vulnerability and secret auditing |
| `prototype_pollution_test` | Prototype pollution testing |
| `websocket_test_unauth` | WebSocket unauthenticated access testing |

### Web Application Security (15+ Tools)
| Tool | Description |
|------|-------------|
| `dir_fuzz` | Directory and file fuzzing |
| `nikto_scan` | Web server security assessment |
| `sqlmap_scan` | SQL injection detection and exploitation |
| `hydra_brute` | Password brute forcing |
| `web_full_scan` | Comprehensive web application assessment |

---

## Ollama Cloud AI

DORAKULA integrates with Ollama Cloud API for AI-powered vulnerability analysis with token-efficient design:

### 3-Tier Model System
| Tier | Model (Default) | Max Tokens | Use Case |
|------|-----------------|------------|----------|
| **Quick** | ministral-3:8b | 150 | Tool recommendations, quick triage |
| **Medium** | gemma3:27b | 300 | Vulnerability analysis, priority ranking |
| **Heavy** | gemma4:31b | 500 | Exploit chain generation, deep analysis |

### Token Efficiency Features
- **AI Cache** — 1-hour TTL cache avoids redundant AI calls
- **Minimal Prompts** — Super concise prompts to save tokens
- **Smart Model Selection** — Automatically picks the right tier for each task
- **`--ai-dry-run`** — Test AI routing without consuming tokens
- **Usage Tracking** — Monitor session and weekly token usage
- **Auto-Fallback** — If a paid model fails, automatically retry with a free model

### Free Cloud Models
```
ministral-3:3b/8b/14b | gemma3:4b/12b/27b | gemma4:31b
rnj-1:8b | devstral-small-2:24b | qwen3-coder:480b | gpt-oss:20b/120b
```

```bash
# Start with Ollama Cloud
python3 dorakula_server.py --ollama-api-key YOUR_KEY

# Test AI without consuming tokens
python3 dorakula_server.py --ai-dry-run

# Custom model selection
python3 dorakula_server.py --ollama-model-quick ministral-3:8b --ollama-model-heavy gemma4:31b
```

---

## WAF Bypass Engine

DORAKULA automatically detects and bypasses Web Application Firewalls:

- **SafeLine WAF** — Custom evasion techniques
- **Cloudflare** — Origin IP discovery and bypass
- **ModSecurity** — Rule-specific bypasses
- **Generic WAF** — Fingerprinting and adaptive evasion

The WAF Bypass Engine integrates with all scanning tools, automatically applying evasion techniques when a WAF is detected.

---

## Deadlock Recovery

When a scan fails or hangs, DORAKULA automatically:
1. Detects the failure type (timeout, WAF block, connection reset)
2. Selects an alternate technique or tool
3. Retries with modified parameters
4. Escalates to AI analysis if repeated failures

---

## Sovereign Mode

National-grade cyber defense capabilities for authorized sovereign security operations:

- **C5ISR Integration** — Command, Control, Communications, Computers, Cyber, Intelligence, Surveillance, Reconnaissance
- **Critical Infrastructure Protection** — ICS/SCADA security assessment
- **Threat Intelligence** — APT attribution and campaign tracking
- **Post-Quantum Readiness** — Quantum-resistant algorithm assessment

> ⚠️ Sovereign Mode is strictly for authorized national cyber defense operations.

---

## API Reference

_Routes below are auto-generated from the Flask `url_map` — 198 real endpoints, not aspirational ones._

**Total: 198 routes** (excluding `/static/<path>`)

All endpoints (except `/health`, `/api/health`, `/api/status`) require `X-API-Key` header.

### AI Agent Endpoints
_Autonomous testing orchestration + tool listing_

| Method | Endpoint |
|--------|----------|
| POST | `/api/agent/execute` |
| POST | `/api/agent/plan` |
| GET | `/api/agent/task/<task_id>` |
| GET | `/api/agent/tasks` |
| GET | `/api/agent/tools` |

### AI Endpoints
_AI-powered analysis, execution, recommendations_

| Method | Endpoint |
|--------|----------|
| POST | `/api/ai/analyze` |
| POST | `/api/ai/execute` |
| POST | `/api/ai/recommend` |

### Reconnaissance & Scanning
_nmap/masscan/rustscan, subfinder/amass, dnsenum, sslscan, whatweb_

| Method | Endpoint |
|--------|----------|
| POST | `/api/recon/amass_enum` |
| POST | `/api/recon/arjun_params` |
| POST | `/api/recon/autorecon` |
| POST | `/api/recon/dnsenum` |
| POST | `/api/recon/dnsrecon` |
| POST | `/api/recon/enum4linux_scan` |
| POST | `/api/recon/fierce_scan` |
| POST | `/api/recon/gobuster_dns` |
| POST | `/api/recon/httpx_probe` |
| POST | `/api/recon/masscan` |
| POST | `/api/recon/netbios_scan` |
| POST | `/api/recon/nmap_scan` |
| POST | `/api/recon/nmap_stealth` |
| POST | `/api/recon/nmap_udp` |
| POST | `/api/recon/paramspider_crawl` |
| POST | `/api/recon/ping_sweep` |
| POST | `/api/recon/rustscan` |
| POST | `/api/recon/smb_enum` |
| POST | `/api/recon/sslscan_tool` |
| POST | `/api/recon/sslyze_scan` |
| POST | `/api/recon/subfinder_enum` |
| POST | `/api/recon/testssl_scan` |
| POST | `/api/recon/theharvester` |
| POST | `/api/recon/traceroute_tool` |
| POST | `/api/recon/whatweb_scan` |

### Web Application Security
_nuclei, nikto, sqlmap, JWT analysis, CORS, LFI, SSRF, cmd injection_

| Method | Endpoint |
|--------|----------|
| POST | `/api/web/api_fuzz_graphql` |
| POST | `/api/web/api_fuzz_rest` |
| POST | `/api/web/api_test_bola` |
| POST | `/api/web/cmd_blind_test` |
| POST | `/api/web/cmd_injection_test` |
| POST | `/api/web/commix_test` |
| POST | `/api/web/content_type_fuzz` |
| POST | `/api/web/cookie_security_check` |
| POST | `/api/web/cors_check` |
| POST | `/api/web/dalfox_xss` |
| POST | `/api/web/dirb_scan` |
| POST | `/api/web/dirsearch_scan` |
| POST | `/api/web/feroxbuster_dir` |
| POST | `/api/web/ffuf_dir` |
| POST | `/api/web/gau_urls` |
| POST | `/api/web/gobuster_dir` |
| POST | `/api/web/graphql_introspect` |
| POST | `/api/web/hakrawler_crawl` |
| POST | `/api/web/header_check` |
| POST | `/api/web/jwt_analyze` |
| POST | `/api/web/jwt_crack` |
| POST | `/api/web/jwt_none_bypass` |
| POST | `/api/web/katana_crawl` |
| POST | `/api/web/lfi_test` |
| POST | `/api/web/lfi_wrapper_test` |
| POST | `/api/web/nikto_scan` |
| POST | `/api/web/nosqlmap_test` |
| POST | `/api/web/nuclei_scan` |
| POST | `/api/web/open_redirect_test` |
| POST | `/api/web/rest_api_fuzz` |
| POST | `/api/web/sqlmap_scan` |
| POST | `/api/web/ssrf_cloud_metadata` |
| POST | `/api/web/ssrf_test` |
| POST | `/api/web/tplmap_test` |
| POST | `/api/web/wafw00f_detect` |
| POST | `/api/web/waybackurls` |
| POST | `/api/web/wfuzz_fuzz` |
| POST | `/api/web/wpscan_enum` |
| POST | `/api/web/xss_payloads` |
| POST | `/api/web/xss_scan` |

### WAF Bypass Engine (v2.5)
_WAF detection, 403 bypass URLs, v3 test variants (XSS/SSRF/LFI/CMDi)_

| Method | Endpoint |
|--------|----------|
| POST | `/api/waf_bypass/403_bypass_urls` |
| POST | `/api/waf_bypass/cmdi_test_v3` |
| GET | `/api/waf_bypass/deadlock_stats` |
| GET | `/api/waf_bypass/info` |
| POST | `/api/waf_bypass/lfi_test_v3` |
| GET | `/api/waf_bypass/smart_scan_status` |
| POST | `/api/waf_bypass/ssrf_test_v3` |
| POST | `/api/waf_bypass/waf_bypass_report` |
| POST | `/api/waf_bypass/waf_detect` |
| POST | `/api/waf_bypass/xss_test_v3` |

### Modern Attack Vectors
_Race conditions, smuggling, takeover, supply chain, prototype pollution, WebSocket_

| Method | Endpoint |
|--------|----------|
| POST | `/api/advanced/cache_poisoning_test` |
| POST | `/api/advanced/csp_bypass_test` |
| POST | `/api/advanced/host_header_injection` |
| POST | `/api/advanced/http_smuggle_clte` |
| POST | `/api/advanced/http_smuggle_tecl` |
| POST | `/api/advanced/idor_test` |
| POST | `/api/advanced/mass_assignment_test` |
| POST | `/api/advanced/prototype_pollution_test` |
| POST | `/api/advanced/race_condition_test` |
| POST | `/api/advanced/request_smuggling` |
| POST | `/api/advanced/subdomain_takeover_check` |
| POST | `/api/advanced/subdomain_takeover_scan` |
| POST | `/api/advanced/supply_chain_audit_js` |
| POST | `/api/advanced/supply_chain_check_sri` |
| POST | `/api/advanced/websocket_test_unauth` |

### OSINT
_Passive recon (Shodan, Censys, HIBP, Sherlock, spiderfoot)_

| Method | Endpoint |
|--------|----------|
| POST | `/api/osint/aquatone_screenshot` |
| POST | `/api/osint/censys_search` |
| POST | `/api/osint/certificate_transparency` |
| POST | `/api/osint/git_dork` |
| POST | `/api/osint/github_secret_scan` |
| POST | `/api/osint/haveibeenpwned_check` |
| POST | `/api/osint/hibp_breach_search` |
| POST | `/api/osint/reconng_module` |
| POST | `/api/osint/sherlock_hunt` |
| POST | `/api/osint/shodan_search` |
| POST | `/api/osint/social_analyzer` |
| POST | `/api/osint/spiderfoot_scan` |
| POST | `/api/osint/subjack_check` |
| POST | `/api/osint/trufflehog_scan` |
| POST | `/api/osint/wayback_machine` |

### Password Cracking
_Hashcat, John, Hydra, Medusa, evil-winrm, netexec_

| Method | Endpoint |
|--------|----------|
| POST | `/api/password/brute_force_custom` |
| POST | `/api/password/evil_winrm` |
| POST | `/api/password/hash_crack_autodetect` |
| POST | `/api/password/hash_identify` |
| POST | `/api/password/hashcat_crack` |
| POST | `/api/password/hydra_brute` |
| POST | `/api/password/john_crack` |
| POST | `/api/password/medusa_brute` |
| POST | `/api/password/netexec_smb` |
| POST | `/api/password/netexec_ssh` |
| POST | `/api/password/password_strength_check` |
| POST | `/api/password/patator_brute` |

### Cloud Security
_AWS/GCP/Azure/K8s/Docker scanners (Prowler, ScoutSuite, kube-hunter, trivy)_

| Method | Endpoint |
|--------|----------|
| POST | `/api/cloud/aws_bucket_check` |
| POST | `/api/cloud/aws_pacu` |
| POST | `/api/cloud/aws_prowler` |
| POST | `/api/cloud/aws_s3_enum` |
| POST | `/api/cloud/azure_scanner` |
| POST | `/api/cloud/checkov_scan` |
| POST | `/api/cloud/cloud_frontier` |
| POST | `/api/cloud/cloud_metadata_ssrf` |
| POST | `/api/cloud/cloudmapper` |
| POST | `/api/cloud/docker_bench` |
| POST | `/api/cloud/gcp_scanner` |
| POST | `/api/cloud/iam_enum` |
| POST | `/api/cloud/k8s_api_check` |
| POST | `/api/cloud/kube_bench` |
| POST | `/api/cloud/kube_hunter` |
| POST | `/api/cloud/s3_bucket_misconfig` |
| POST | `/api/cloud/scout_suite` |
| POST | `/api/cloud/serverless_scan` |
| POST | `/api/cloud/terrascan_scan` |
| POST | `/api/cloud/trivy_scan` |

### Binary Analysis
_Reverse engineering & exploitation (angr, ghidra, radare2, gdb, pwntools)_

| Method | Endpoint |
|--------|----------|
| POST | `/api/binary/angr_analyze` |
| POST | `/api/binary/binwalk_extract` |
| POST | `/api/binary/checksec_tool` |
| POST | `/api/binary/gdb_debug` |
| POST | `/api/binary/ghidra_analyze` |
| POST | `/api/binary/msfvenom_generate` |
| POST | `/api/binary/objdump_analyze` |
| POST | `/api/binary/pwntools_exploit` |
| POST | `/api/binary/radare2_analyze` |
| POST | `/api/binary/readelf_analyze` |
| POST | `/api/binary/ropgadget_find` |
| POST | `/api/binary/ropper_find` |
| POST | `/api/binary/strings_extract` |
| POST | `/api/binary/upx_unpack` |
| POST | `/api/binary/volatility_analyze` |

### Browser Automation
_Headless browser crawl, DOM analysis, screenshot, cookie audit_

| Method | Endpoint |
|--------|----------|
| POST | `/api/browser/browser_cookie_analyze` |
| POST | `/api/browser/browser_crawl` |
| POST | `/api/browser/browser_dom_analyze` |
| POST | `/api/browser/browser_form_detect` |
| POST | `/api/browser/browser_js_execute` |
| POST | `/api/browser/browser_network_monitor` |
| POST | `/api/browser/browser_performance` |
| POST | `/api/browser/browser_proxy_check` |
| POST | `/api/browser/browser_screenshot` |
| POST | `/api/browser/browser_security_headers` |

### CTF Toolkit
_Stego, forensics, crypto, memory analysis_

| Method | Endpoint |
|--------|----------|
| POST | `/api/ctf/base64_tool` |
| POST | `/api/ctf/binwalk_firmware` |
| POST | `/api/ctf/cipher_identify` |
| POST | `/api/ctf/cyberchef_decode` |
| POST | `/api/ctf/exiftool_read` |
| POST | `/api/ctf/foremost_recover` |
| POST | `/api/ctf/frequency_analysis` |
| POST | `/api/ctf/hash_crack_ctf` |
| POST | `/api/ctf/memory_strings` |
| POST | `/api/ctf/pcaps_analyze` |
| POST | `/api/ctf/photorec_recover` |
| POST | `/api/ctf/registry_parse` |
| POST | `/api/ctf/steghide_extract` |
| POST | `/api/ctf/volatility3_mem` |
| POST | `/api/ctf/zsteg_detect` |

### Vulnerability Intelligence
_CVE lookup, ExploitDB search, recent critical advisories_

| Method | Endpoint |
|--------|----------|
| GET | `/api/intel/advisory` |
| POST | `/api/intel/cve/<cve_id>` |
| POST | `/api/intel/exploitdb` |
| GET | `/api/intel/recent_critical` |

### Cache Management
_Internal result cache stats & clear_

| Method | Endpoint |
|--------|----------|
| POST | `/api/cache/clear` |
| GET | `/api/cache/stats` |

### Database Stats
_SQLite DB stats_

| Method | Endpoint |
|--------|----------|
| GET | `/api/db/stats` |

### Dynamic Route (Generic Tool Runner)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/run/<tool_name>` | Generic dispatcher — runs any of 192 MCP tools by name. Body = tool parameters. |

### Parameterized Routes

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/task/<task_id>` | Poll async task status (returned by heavy tools: nmap, nuclei, etc) |
| GET | `/api/agent/task/<task_id>` | Same — agent variant |
| GET | `/api/intel/cve/<cve_id>` | CVE lookup by ID (e.g. CVE-2024-1234) |
| GET | `/static/<path:filename>` | Static asset serving |

## MCP Integration

### Claude Desktop
```json
{
  "mcpServers": {
    "dorakula": {
      "command": "python3",
      "args": ["/path/to/dorakula/dorakula_server.py"],
      "description": "DORAKULA v3.1 Cloud - Offensive Security MCP Platform",
      "timeout": 300
    }
  }
}
```

### Cursor / VS Code
Use the included `dorakula-mcp.json` as a template for MCP server configuration.

---

## Project Structure

```
dorakula/
├── dorakula_server.py          # Main server (REST + MCP) — 167+ tools
├── agents/                     # AI agent modules
│   ├── ai_router.py           # Ollama Cloud AI router with 3-tier system
│   ├── xss_scanner.py         # XSS vulnerability scanning
│   ├── ssrf_tester.py         # SSRF vulnerability testing
│   ├── lfi_tester.py          # LFI vulnerability testing
│   ├── cmd_injection.py       # Command injection testing
│   ├── jwt_analyzer.py        # JWT security analysis
│   └── api_fuzzer.py          # API security fuzzing
├── advanced/                   # Modern attack vector modules
│   ├── race_condition.py      # Race condition detection
│   ├── http_smuggling.py      # HTTP request smuggling
│   ├── subdomain_takeover.py  # Subdomain takeover detection
│   ├── supply_chain_auditor.py # Supply chain auditing
│   ├── prototype_pollution.py # Prototype pollution testing
│   ├── websocket_tester.py    # WebSocket security testing
│   ├── vuln_chainer.py        # Vulnerability chain correlation
│   └── sovereign_mode.py      # Sovereign Mode capabilities
├── core/                       # Core infrastructure
│   ├── database.py            # SQLite database management
│   ├── session_manager.py     # Testing session management
│   ├── report_generator.py    # Professional report generation
│   ├── scope_guard.py         # Target scope validation
│   └── sandbox.py             # Dangerous command blocking
├── .env.example               # Environment configuration template
├── requirements.txt           # Python dependencies
└── LICENSE                    # MIT License
```

---

## Security & Legal

<div align="center">

**⚠️ WARNING: This tool is for AUTHORIZED security testing only. ⚠️**

</div>

**Authorized Use:**
- ✅ Bug bounty programs with explicit authorization
- ✅ Penetration testing with signed scope agreements
- ✅ Security research on systems you own
- ✅ CTF competitions and educational purposes
- ✅ Authorized national cyber defense operations

**Forbidden:**
- ❌ Testing systems without explicit permission
- ❌ Exploiting vulnerabilities for personal gain
- ❌ Using this tool for illegal activities

---

## License

MIT License — see [LICENSE](LICENSE) file for details.

---

## Author

**dorakula** — [GitHub](https://github.com/dorakula)

---

<div align="center">

**If DORAKULA helps your security research, give it a ⭐!**

</div>
