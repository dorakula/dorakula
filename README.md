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

### Server Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Server health check |
| `/api/status` | GET | Server status with AI usage stats |
| `/api/agent/tools` | GET | List all available tools |
| `/api/agent/plan` | POST | Plan tool chain for objective |
| `/api/agent/execute` | POST | Execute AI agent task |

### AI Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ai/tool_recommend` | POST | Get AI-powered tool recommendation |
| `/api/ai/vuln_analyze` | POST | AI vulnerability analysis |
| `/api/ai/exploit_chain` | POST | AI exploit chain generation |
| `/api/ai/priority_rank` | POST | AI vulnerability priority ranking |

### Security Testing Endpoints

| Category | Endpoints |
|----------|-----------|
| **Recon** | `/api/recon/nmap`, `/api/recon/nuclei`, `/api/recon/subfinder`, `/api/recon/httpx` |
| **Web** | `/api/web/dirfuzz`, `/api/web/nikto`, `/api/web/sqlmap` |
| **XSS** | `/api/xss/scan`, `/api/xss/payloads` |
| **SSRF** | `/api/ssrf/test`, `/api/ssrf/cloud-metadata` |
| **LFI** | `/api/lfi/test`, `/api/lfi/wrapper-test` |
| **JWT** | `/api/jwt/analyze`, `/api/jwt/crack`, `/api/jwt/forge` |
| **API** | `/api/api-fuzz/rest`, `/api/api-fuzz/graphql` |
| **Advanced** | `/api/race-condition/test`, `/api/smuggling/test`, `/api/subdomain-takeover/scan` |
| **Supply Chain** | `/api/supply-chain/audit`, `/api/prototype-pollution/test`, `/api/websocket/test` |

---

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
