# 📦 DORAKULA Installation Guide

> **Read this entire file before starting.** Skipping steps = broken installation.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Linux Installation (Kali / Ubuntu / Debian)](#2-linux-installation)
3. [Windows Installation](#3-windows-installation)
4. [Docker Installation (Cross-Platform)](#4-docker-installation)
5. [Configuration](#5-configuration)
6. [Starting the Server](#6-starting-the-server)
7. [Verification](#7-verification)
8. [MCP Client Setup (Claude Desktop / Cursor)](#8-mcp-client-setup)
9. [Installing Security Tools](#9-installing-security-tools)
10. [Troubleshooting](#10-troubleshooting)
11. [Post-Installation Checklist](#11-post-installation-checklist)

---

## 1. Prerequisites

### Minimum Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Python** | 3.10+ | 3.13+ |
| **RAM** | 2 GB | 4 GB+ |
| **Disk** | 500 MB (code + deps) | 5 GB (code + deps + security tools) |
| **OS** | Linux x64 / Windows 10+ / macOS | Kali Linux 2024+ |
| **Network** | Internet access for pip + Ollama Cloud | — |

### Required Software (All Platforms)

| Software | Purpose | Check Command |
|----------|---------|---------------|
| **Python 3.10+** | Runtime | `python3 --version` (Linux) / `python --version` (Windows) |
| **pip** | Package installer | `pip3 --version` (Linux) / `pip --version` (Windows) |
| **git** | Clone repository | `git --version` |
| **venv** | Virtual environment | `python3 -c "import venv; print('OK')"` (Linux) |

> ⚠️ **If any check above fails, install the missing software before continuing.**

---

## 2. Linux Installation

### 2.1 Install Prerequisites

#### Kali Linux / Debian / Ubuntu

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python + pip + git + venv + build tools
sudo apt install -y python3 python3-pip python3-venv git build-essential

# Verify installation
python3 --version    # Must show 3.10 or higher
pip3 --version       # Must show pip version
git --version        # Must show git version
python3 -c "import venv; print('venv: OK')"  # Must show "venv: OK"
```

#### Arch Linux / Manjaro

```bash
sudo pacman -Syu --noconfirm python python-pip git base-devel
python --version
pip --version
git --version
```

#### Fedora / RHEL

```bash
sudo dnf install -y python3 python3-pip git gcc gcc-c++ make
python3 --version
pip3 --version
git --version
```

### 2.2 Clone Repository

```bash
# Choose installation directory
cd /opt    # or any directory you prefer

# Clone (use your fork URL if you forked the repo)
sudo git clone https://github.com/dorakula/dorakula.git
sudo chown -R $USER:$USER dorakula
cd dorakula
```

### 2.3 Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv dorakula-env

# Activate it
source dorakula-env/bin/activate

# Verify activation (prompt should show "(dorakula-env)")
which python   # Should show /opt/dorakula/dorakula-env/bin/python
python --version
```

> ⚠️ **You MUST activate the virtual environment before every step below.**
> If you close your terminal, re-activate with: `source dorakula-env/bin/activate`

### 2.4 Install Python Dependencies

```bash
# Make sure venv is activated!
# Upgrade pip first
pip install --upgrade pip

# Install production dependencies
pip install -r requirements.txt

# Install development dependencies (optional, for testing)
pip install -r requirements.dev.txt
```

**Expected output**: pip downloads ~20 packages, no errors. If you see red text, check [Troubleshooting](#10-troubleshooting).

**Verify installation**:

```bash
python -c "import flask, mcp, fastmcp, starlette, uvicorn, requests, urllib3, aiohttp, websockets, websocket, dns, psutil, pydantic; print('ALL IMPORTS OK')"
```

> If this prints `ALL IMPORTS OK`, proceed. If not, check [Troubleshooting](#10-troubleshooting).

### 2.5 Configure Environment

```bash
# Copy the example config
cp .env.example .env

# Edit .env with your settings
nano .env    # or: vim .env, code .env
```

**Minimum .env for testing (no AI)**:

```ini
DORAKULA_HOST=127.0.0.1
DORAKULA_PORT=9092
DORAKULA_DEBUG=false
DORAKULA_API_KEY=change-this-to-a-strong-random-string
```

**Full .env with AI (requires Ollama Cloud account)**:

```ini
DORAKULA_HOST=127.0.0.1
DORAKULA_PORT=9092
DORAKULA_DEBUG=false
DORAKULA_API_KEY=your-strong-random-api-key-here

# Ollama Cloud (get keys from https://ollama.com)
OLLAMA_API_KEY_1=your-first-ollama-key
OLLAMA_API_KEY_2=your-second-ollama-key
OLLAMA_API_URL=https://ollama.com
OLLAMA_MODEL_QUICK=ministral-3:8b
OLLAMA_MODEL_HEAVY=gemma4:31b
```

**Set file permissions** (important for security):

```bash
chmod 600 .env    # Only owner can read/write
```

### 2.6 Load Environment Variables

DORAKULA reads environment variables from `.env` via shell sourcing:

```bash
# Load .env into current shell session
set -a
source .env
set +a

# Verify variables are loaded
echo $DORAKULA_API_KEY    # Should show your API key
echo $OLLAMA_API_KEY_1    # Should show your first Ollama key (if set)
```

> ⚠️ **You MUST run `set -a; source .env; set +a` before starting the server.**
> If you open a new terminal, repeat this step.

---

## 3. Windows Installation

### 3.1 Install Prerequisites

#### Step 1: Install Python 3.13+

1. Go to https://www.python.org/downloads/
2. Download **Python 3.13.x** Windows installer (64-bit)
3. Run installer — **CHECK "Add Python to PATH"** (critical!)
4. Click "Install Now"
5. Verify:

```powershell
python --version    # Must show 3.13.x
pip --version       # Must show pip version
```

> ⚠️ If `python --version` shows "command not found", Python is not in PATH.
> Re-run installer → "Modify" → check "Add Python to environment variables".

#### Step 2: Install Git

1. Go to https://git-scm.com/download/win
2. Download and run installer (use default settings)
3. Verify:

```powershell
git --version
```

#### Step 3: Install Visual C++ Build Tools (Required for some packages)

Some Python packages (aiohttp, etc.) need C compiler on Windows:

1. Go to https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Download "Build Tools for Visual Studio"
3. Run installer → select "Desktop development with C++"
4. Install (takes ~3 GB disk space)

> If you skip this, `pip install -r requirements.txt` may fail on `aiohttp`.

#### Step 4: Create Project Directory

```powershell
# Choose installation directory
mkdir C:\dorakula
cd C:\dorakula
```

### 3.2 Clone Repository

```powershell
git clone https://github.com/dorakula/dorakula.git .
```

> The `.` at the end clones into current directory (not a subdirectory).

### 3.3 Create Virtual Environment

```powershell
# Create virtual environment
python -m venv dorakula-env

# Activate it
dorakula-env\Scripts\activate

# Verify activation (prompt should show "(dorakula-env)")
where python    # Should show C:\dorakula\dorakula-env\Scripts\python.exe
python --version
```

> ⚠️ **You MUST activate the virtual environment before every step below.**
> If you close PowerShell, re-activate with: `dorakula-env\Scripts\activate`
>
> If you get "execution of scripts is disabled" error, run as Administrator:
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### 3.4 Install Python Dependencies

```powershell
# Make sure venv is activated!
pip install --upgrade pip

pip install -r requirements.txt

pip install -r requirements.dev.txt
```

**Verify installation**:

```powershell
python -c "import flask, mcp, fastmcp, starlette, uvicorn, requests, urllib3, aiohttp, websockets, websocket, dns, psutil, pydantic; print('ALL IMPORTS OK')"
```

### 3.5 Configure Environment

```powershell
# Copy the example config
copy .env.example .env

# Edit .env with Notepad
notepad .env
```

**Minimum .env for testing (no AI)**:

```ini
DORAKULA_HOST=127.0.0.1
DORAKULA_PORT=9092
DORAKULA_DEBUG=false
DORAKULA_API_KEY=change-this-to-a-strong-random-string
```

### 3.6 Set Environment Variables (Windows)

```powershell
# Load .env variables into current PowerShell session
Get-Content .env | ForEach-Object {
    if ($_ -match "^\s*([^#][^=]+)=(.*)$") {
        Set-Item -Path "Env:$($Matches[1].Trim())" -Value $Matches[2].Trim()
    }
}

# Verify
echo $env:DORAKULA_API_KEY
```

> ⚠️ You MUST run this before starting the server in a new PowerShell window.
> Alternative: Set system environment variables via System Properties → Environment Variables.

---

## 4. Docker Installation

### 4.1 Install Docker

**Linux**:
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
# Log out and log back in for group change to take effect
```

**Windows**: Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### 4.2 Build and Run

```bash
# In the dorakula directory:
docker-compose up -d

# Check if running
docker-compose ps
curl http://127.0.0.1:9093/api/health
```

### 4.3 Docker with AI

Create a `.env` file before running docker-compose:

```bash
# .env file (same directory as docker-compose.yml)
DORAKULA_API_KEY=your-strong-key
OLLAMA_API_KEY_1=your-first-ollama-key
OLLAMA_API_KEY_2=your-second-ollama-key
```

```bash
docker-compose up -d
```

### 4.4 View Logs

```bash
docker-compose logs -f dorakula
```

### 4.5 Stop

```bash
docker-compose down
```

---

## 5. Configuration

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DORAKULA_API_KEY` | ✅ Yes | (random) | API key for authentication. If not set, a random key is generated and printed at startup. |
| `DORAKULA_HOST` | No | `127.0.0.1` | Bind address. Use `0.0.0.0` for Docker. |
| `DORAKULA_PORT` | No | `9092` | MCP SSE port. REST API = port + 1 (9093). |
| `DORAKULA_DEBUG` | No | `false` | Enable debug logging. |
| `OLLAMA_API_KEY_1..10` | No | (empty) | Ollama Cloud API keys (rotation pool). |
| `OLLAMA_API_URL` | No | `https://ollama.com` | Ollama Cloud API URL. |
| `OLLAMA_MODEL_QUICK` | No | `ministral-3:8b` | Fast model for quick tasks. |
| `OLLAMA_MODEL_HEAVY` | No | `gemma4:31b` | Powerful model for complex analysis. |
| `DORAKULA_HMAC_SECRET` | No | (random) | HMAC secret for request signature verification. |

### Generate a Strong API Key

```bash
# Linux / macOS
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Windows
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the output into your `.env` file as `DORAKULA_API_KEY`.

---

## 6. Starting the Server

### Linux

```bash
# 1. Navigate to dorakula directory
cd /opt/dorakula    # or wherever you cloned

# 2. Activate virtual environment
source dorakula-env/bin/activate

# 3. Load environment variables
set -a
source .env
set +a

# 4. Start server (without AI)
python dorakula_server.py --no-ai

# 4. OR: Start server (with AI, requires OLLAMA_API_KEY set)
python dorakula_server.py

# 5. OR: Start with custom port
python dorakula_server.py --port 8080 --no-ai
```

### Windows

```powershell
# 1. Navigate to dorakula directory
cd C:\dorakula

# 2. Activate virtual environment
dorakula-env\Scripts\activate

# 3. Load environment variables (PowerShell)
Get-Content .env | ForEach-Object {
    if ($_ -match "^\s*([^#][^=]+)=(.*)$") {
        Set-Item -Path "Env:$($Matches[1].Trim())" -Value $Matches[2].Trim()
    }
}

# 4. Start server (without AI)
python dorakula_server.py --no-ai

# 4. OR: Start server (with AI)
python dorakula_server.py
```

### Expected Startup Output

```
2026-06-24 13:42:20 - dorakula - INFO - WAF Bypass Engine + Deadlock Recovery: ACTIVE
2026-06-24 13:42:20 - dorakula - INFO - Advanced Modules (...): ACTIVE
2026-06-24 13:42:20 - dorakula - INFO - AIRouter: 5 Ollama API key(s) loaded (rotation pool)
2026-06-24 13:42:26 - dorakula - INFO - Ollama Cloud API connected! Available models: 35
2026-06-24 13:42:27 - dorakula - INFO - FastMCP server initialized with 192 tools
2026-06-24 13:42:27 - dorakula - INFO - MCP tools registered: 192 tools + 6 AI/intel + 6 DARK CORE tools
2026-06-24 13:42:27 - dorakula - INFO - REST API started on 127.0.0.1:9093
2026-06-24 13:42:27 - dorakula - INFO - Starting MCP SSE server on 127.0.0.1:9092

  [SECURITY] No --api-key or DORAKULA_API_KEY env var set.
  [SECURITY] Generated ephemeral API key for this session:
  [SECURITY]   Xy7M_wVlDJp0jnePQy4aIpe4iZqnKTZYVt9TNgM18
  [SECURITY] Set DORAKULA_API_KEY env var to make it persistent.

    ╔══════════════════════════════════════════════════════╗
    ║   🧛 DORAKULA v3.1.0 - Offensive Security    ║
    ║   Build: 2026.06.01-v3.1-cloud (ALL-IN-ONE)               ║
    ║   The Night Stalker of Cyberspace                    ║
    ╚══════════════════════════════════════════════════════╝
```

> ⚠️ **Save the API key!** If you see "[SECURITY] Generated ephemeral API key",
> copy it — you need it for all API calls. To make it persistent, set
> `DORAKULA_API_KEY` in your `.env` file.

### Server Endpoints

| Service | URL | Auth Required |
|---------|-----|---------------|
| REST API | `http://127.0.0.1:9093` | Yes (`X-API-Key` header) |
| MCP SSE | `http://127.0.0.1:9092/sse` | Session-based |
| Health Check | `http://127.0.0.1:9093/api/health` | No |
| Swagger UI | `http://127.0.0.1:9093/api/docs` | No |
| OpenAPI Spec | `http://127.0.0.1:9093/api/openapi.json` | No |
| Prometheus Metrics | `http://127.0.0.1:9093/metrics` | No |

---

## 7. Verification

Run these commands to verify your installation is working:

### 7.1 Health Check

```bash
curl http://127.0.0.1:9093/api/health
```

**Expected**: `{"status":"healthy","version":"3.1.0","tools_registered":192,...}`

### 7.2 API Authentication

```bash
# Replace YOUR_API_KEY with the key from startup log or .env
API_KEY="YOUR_API_KEY"

# Should return 401 without key
curl http://127.0.0.1:9093/api/agent/tools

# Should return 200 with key
curl -H "X-API-Key: $API_KEY" http://127.0.0.1:9093/api/agent/tools
```

### 7.3 Tool Execution

```bash
# Analyze a JWT token
curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}' \
  http://127.0.0.1:9093/api/web/jwt_analyze
```

**Expected**: JSON with `status: "success"`, header (alg: HS256), payload, findings.

### 7.4 AI Test (if Ollama keys configured)

```bash
curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","context":"web"}' \
  http://127.0.0.1:9093/api/ai/recommend
```

**Expected**: JSON with `ai_recommendation` and `all_phases` (tool chain).

### 7.5 Run Test Suite

```bash
# In a new terminal (keep server running):
source dorakula-env/bin/activate    # Linux
# dorakula-env\Scripts\activate     # Windows

export DORAKULA_API_KEY="YOUR_API_KEY"    # Linux
# $env:DORAKULA_API_KEY="YOUR_API_KEY"   # Windows PowerShell

pytest tests/ -v -k "not rate_limit"
```

**Expected**: `88 passed, 1 deselected in ~16s`

---

## 8. MCP Client Setup

### Claude Desktop

Edit `claude_desktop_config.json`:

**Linux**: `~/.config/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "dorakula": {
      "command": "python",
      "args": ["/path/to/dorakula/dorakula_server.py"],
      "env": {
        "DORAKULA_API_KEY": "your-api-key-here",
        "OLLAMA_API_KEY_1": "your-ollama-key-here"
      },
      "timeout": 300
    }
}
```

> Replace `/path/to/dorakula/` with your actual installation path.
> On Windows, use backslashes: `C:\\dorakula\\dorakula_server.py`
> Use the full path to your venv Python if needed: `/opt/dorakula/dorakula-env/bin/python`

### Cursor

Edit `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "dorakula": {
      "command": "python",
      "args": ["/path/to/dorakula/dorakula_server.py"],
      "env": {
        "DORAKULA_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### VS Code (with MCP extension)

Use the included `dorakula-mcp.json` as a template:

```bash
cp dorakula-mcp.json .vscode/mcp.json
# Edit the path to point to your installation
```

---

## 9. Installing Security Tools

DORAKULA can call external security tools (nmap, sqlmap, nuclei, etc.) if they are installed on your system. Without them, DORAKULA still works but tool execution returns "tool not found".

### Kali Linux (Recommended)

Kali Linux includes most security tools by default. To install missing ones:

```bash
sudo apt update
sudo apt install -y nmap masscan subfinder httpx-toolkit whatweb \
  nuclei nikto sqlmap gobuster ffuf feroxbuster wafw00f \
  hydra john hashcat dirb dirsearch commix wpscan \
  sslscan sslyze dnsrecon dnsenum fierce enum4linux \
  theharvester arjun traceroute nbtscan

# Install Go-based tools (if not in apt)
sudo go install github.com/projectdiscovery/katana/cmd/katana@latest
sudo go install github.com/lc/gau@latest
sudo go install github.com/hahwul/dalfox/v2@latest
```

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y nmap nikto sqlmap dirb gobuster \
  hydra john sslscan dnsrecon traceroute

# Install Go (required for some tools)
sudo apt install -y golang-go

# Install Go-based tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/epi052/feroxbuster@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

### Windows

Security tools on Windows are limited. Recommended approach:

1. **Use WSL2 (Windows Subsystem for Linux)** with Kali Linux:
   ```powershell
   wsl --install -d kali-linux
   ```
   Then follow the [Linux Installation](#2-linux-installation) guide inside WSL.

2. **Install individual tools** (Windows binaries):
   - [nmap](https://nmap.org/download.html)
   - [sqlmap](https://github.com/sqlmapproject/sqlmap/wiki/Installation)
   - [nuclei](https://github.com/projectdiscovery/nuclei/releases)
   - [subfinder](https://github.com/projectdiscovery/subfinder/releases)
   - [httpx](https://github.com/projectdiscovery/httpx/releases)

   Add each tool's directory to your system `PATH`.

### Verify Tool Availability

```bash
# Linux (with venv activated)
python -c "
import sys; sys.path.insert(0, '.')
from dorakula_server import DorakulaConfig, DorakulaFlaskApp
app = DorakulaFlaskApp(DorakulaConfig())
tools = app.executor.available_tools()
print(f'{len(tools)} security tools available:')
for t in tools[:10]:
    print(f'  {t}')
print('  ...' if len(tools) > 10 else '')
"

# Or via API (server must be running)
curl -H "X-API-Key: $DORAKULA_API_KEY" http://127.0.0.1:9093/api/agent/tools | python -m json.tool | head -20
```

---

## 10. Troubleshooting

### Problem: `python3: command not found` (Linux)

**Solution**: Python is not installed or not in PATH.

```bash
sudo apt install python3      # Debian/Ubuntu/Kali
sudo dnf install python3      # Fedora
sudo pacman -S python          # Arch
```

### Problem: `pip: command not found`

**Solution**: Install pip.

```bash
sudo apt install python3-pip    # Debian/Ubuntu/Kali
python3 -m ensurepip --upgrade  # Alternative
```

### Problem: `python: command not found` (Windows)

**Solution**: Python is not in PATH.

1. Re-run Python installer → "Modify" → check "Add Python to environment variables"
2. Or manually add to PATH:
   - Settings → System → About → Advanced system settings → Environment Variables
   - Add `C:\Users\YOUR_USERNAME\AppData\Local\Programs\Python\Python313\` to PATH
   - Add `C:\Users\YOUR_USERNAME\AppData\Local\Programs\Python\Python313\Scripts\` to PATH
3. Restart PowerShell

### Problem: `pip install` fails with `error: Microsoft Visual C++ 14.0 is required` (Windows)

**Solution**: Install Visual C++ Build Tools.

1. Go to https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Download "Build Tools for Visual Studio"
3. Run installer → select "Desktop development with C++"
4. Re-run `pip install -r requirements.txt`

### Problem: `pip install` fails with `error: command 'gcc' failed` (Linux)

**Solution**: Install build tools.

```bash
sudo apt install build-essential python3-dev   # Debian/Ubuntu/Kali
sudo dnf install gcc gcc-c++ python3-devel      # Fedora
sudo pacman -S base-devel python                # Arch
```

### Problem: `ModuleNotFoundError: No module named 'flask'`

**Solution**: Virtual environment is not activated.

```bash
# Linux
source dorakula-env/bin/activate

# Windows
dorakula-env\Scripts\activate
```

Verify: `which python` (Linux) or `where python` (Windows) should show the venv path.

### Problem: `Address already in use` (port 9092 or 9093)

**Solution**: Another process is using the port.

```bash
# Linux: find and kill the process
sudo lsof -i :9092
sudo kill -9 <PID>

# Or use a different port
python dorakula_server.py --port 8080
```

```powershell
# Windows: find and kill the process
netstat -ano | findstr :9092
taskkill /PID <PID> /F
```

### Problem: `Unauthorized - API key required` on every request

**Solution**: You're not sending the API key, or the key is wrong.

```bash
# Check what key the server is using
# Look at startup log for "[SECURITY]   <key>"

# Send the key in the header
curl -H "X-API-Key: YOUR_KEY_HERE" http://127.0.0.1:9093/api/agent/tools
```

### Problem: `Rate limit exceeded` (429)

**Solution**: You've sent more than 100 requests in 60 seconds.

Wait 60 seconds, or use the `Retry-After` header value from the response.

### Problem: Server starts but AI features don't work

**Check**:
1. Is `OLLAMA_API_KEY_1` set in `.env`?
2. Did you run `set -a; source .env; set +a` (Linux) before starting?
3. Check startup log for "Ollama Cloud API connected!" — if missing, keys are not loaded.

### Problem: `ImportError: cannot import name 'X' from 'dorakula_server'`

**Solution**: Stale `.pyc` cache files.

```bash
# Linux
find . -name "__pycache__" -type d -exec rm -rf {} +
find . -name "*.pyc" -delete

# Windows
Get-ChildItem -Path . -Filter __pycache__ -Directory -Recurse | Remove-Item -Recurse -Force
Get-ChildItem -Path . -Filter *.pyc -Recurse | Remove-Item -Force
```

### Problem: `Execution of scripts is disabled` (Windows PowerShell)

**Solution**: Change execution policy.

```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Problem: `.env` file not loading (Linux)

**Solution**: Ensure you source the file correctly.

```bash
# CORRECT:
set -a
source .env
set +a

# Verify:
echo $DORAKULA_API_KEY    # Should show your key

# If empty, check .env file format (no spaces around =)
cat .env | grep DORAKULA_API_KEY
```

### Problem: Docker container exits immediately

**Check logs**:

```bash
docker-compose logs dorakula
```

**Common causes**:
- Missing `DORAKULA_API_KEY` environment variable
- Port already in use on host
- Permission issues with volume mount

---

## 11. Post-Installation Checklist

Run through this checklist to confirm everything is working:

- [ ] Python 3.10+ installed (`python3 --version`)
- [ ] git installed (`git --version`)
- [ ] Repository cloned (`ls dorakula_server.py`)
- [ ] Virtual environment created (`ls dorakula-env/`)
- [ ] Virtual environment activated (`which python` shows venv path)
- [ ] Dependencies installed (`python -c "import flask; print('OK')"`)
- [ ] `.env` file created (`cat .env`)
- [ ] `.env` loaded (`echo $DORAKULA_API_KEY` shows your key)
- [ ] Server starts without errors (`python dorakula_server.py --no-ai`)
- [ ] Health check passes (`curl http://127.0.0.1:9093/api/health`)
- [ ] API auth works (`curl -H "X-API-Key: $KEY" http://127.0.0.1:9093/api/agent/tools`)
- [ ] JWT analysis works (Section 7.3)
- [ ] MCP SSE responds (`curl -N http://127.0.0.1:9092/sse` returns `event: endpoint`)
- [ ] OpenAPI spec accessible (`curl http://127.0.0.1:9093/api/openapi.json | head`)
- [ ] Swagger UI loads (open `http://127.0.0.1:9093/api/docs` in browser)
- [ ] Metrics endpoint works (`curl http://127.0.0.1:9093/metrics`)
- [ ] Tests pass (`pytest tests/ -v -k "not rate_limit"`)

**If all checkboxes are checked, your installation is complete and verified.**

---

## Need Help?

- 📖 [Architecture Documentation](ARCHITECTURE.md)
- 🤝 [Contributing Guide](CONTRIBUTING.md)
- 🐛 [Report an Issue](https://github.com/dorakula/dorakula/issues)
- 🔒 [Security Policy](SECURITY.md)

---

*DORAKULA v3.1.0 — The Night Stalker of Cyberspace*
