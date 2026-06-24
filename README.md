<div align="center">

# 🧛 DORAKULA v3.1.0

**The Night Stalker of Cyberspace — Offensive Security MCP Platform**

[![Version](https://img.shields.io/badge/Version-3.1.0-crimson?style=for-the-badge&logo=python&logoColor=white)]
[![License](https://img.shields.io/badge/License-MIT-1a1a1a?style=for-the-badge&logo=github&logoColor=white)]

> ⚠️ WARNING: This tool is for AUTHORIZED security testing only. Unauthorized use is illegal.

</div>

---

## Ringkasan Singkat
DORAKULA adalah platform offensive security berbasis Python yang menyediakan:

- 219 REST endpoints · 192 MCP tools
- Integrasi Ollama Cloud AI (opsional) dengan rotasi kunci
- WAF Bypass Engine, Advanced Modules, Docker-ready

---

## Daftar Isi
1. [Fitur Utama](#fitur-utama)
2. [Persiapan Cepat (Quick Start)](#persiapan-cepat-quick-start)
3. [Endpoint & Mekanisme API](#endpoint--mekanisme-api)
4. [Contoh Pemanggilan API (curl / Python / Node)](#contoh-pemanggilan-api-curl--python--node)
5. [Docker](#docker)
6. [Testing](#testing)
7. [Struktur Proyek](#struktur-proyek)
8. [Roadmap & Legal](#roadmap--legal)
9. [Lisensi & Bantuan](#lisensi--bantuan)

---

## Fitur Utama
| Fitur | Deskripsi |
|-------|-----------|
| Interface | REST API (Flask) + MCP SSE (Starlette) |
| AI | Ollama Cloud integration (rotasi hingga 10 kunci) |
| Tools | 192 security tools (nmap, sqlmap, nuclei, dll.) |
| Observability | Prometheus metrics, OpenAPI/Swagger, audit logging |
| Security | API key auth, rate limiting, HMAC optional, audit logs |
| Deployment | Docker + docker-compose, persistent volumes |

---

## Persiapan Cepat (Quick Start)
```bash
git clone https://github.com/dorakula/dorakula.git
cd dorakula

python3 -m venv dorakula-env
source dorakula-env/bin/activate

pip install -r requirements.txt -r requirements.dev.txt

# Start server (API key auto-generated if not set)
python dorakula_server.py --no-ai
```

Jika menggunakan AI: buat `.env` berisi `OLLAMA_API_KEY_1=...` dan `DORAKULA_API_KEY=...` lalu jalankan tanpa `--no-ai`.

---

## Endpoint & Mekanisme API
Ringkasan endpoint penting:

| Service | URL | Auth |
|---------|-----:|:----:|
| REST API (base) | `http://127.0.0.1:9093` | X-API-Key header |
| MCP SSE | `http://127.0.0.1:9092/sse` | Session-based |
| Health | `/api/health` | None |
| Tools list | `/api/agent/tools` | X-API-Key required |
| JWT analyze | `/api/web/jwt_analyze` | X-API-Key required |
| AI recommend | `/api/ai/recommend` | X-API-Key + Ollama keys (optional) |
| Swagger UI | `/api/docs` | None |
| OpenAPI spec | `/api/openapi.json` | None |
| Prometheus metrics | `/metrics` | None |

Autentikasi:
- Semua request yang butuh auth harus menyertakan header:
  - `X-API-Key: <YOUR_API_KEY>`
- Optional: HMAC signature via `X-Dorakula-Signature` (jika diaktifkan di konfigurasi).

Rate limiting:
- Default: 100 requests / 60s per IP
- Per-endpoint decorator `_rate_limit(per_minute=N)` dapat diberlakukan.

---

## Contoh Pemanggilan API (curl / Python / Node)
1) Mendapatkan daftar tools (curl)
```bash
API_KEY="YOUR_API_KEY"
curl -H "X-API-Key: $API_KEY" http://127.0.0.1:9093/api/agent/tools | jq .
```

2) JWT Analyze (curl)
```bash
curl -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJhbGciOiJIUzI1NiJ9..."}' \
  http://127.0.0.1:9093/api/web/jwt_analyze
```

3) AI Recommend (curl)
```bash
curl -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","context":"web"}' \
  http://127.0.0.1:9093/api/ai/recommend
```

4) Python (requests)
```python
import requests
API_KEY = "YOUR_API_KEY"
url = "http://127.0.0.1:9093/api/web/jwt_analyze"
payload = {"token": "eyJhbGciOiJIUzI1NiJ9..."}
resp = requests.post(url, json=payload, headers={"X-API-Key": API_KEY}, timeout=30)
print(resp.status_code)
print(resp.json())
```

5) Node.js (fetch)
```js
const fetch = require('node-fetch');
const API_KEY = 'YOUR_API_KEY';
const res = await fetch('http://127.0.0.1:9093/api/agent/tools', {
  headers: { 'X-API-Key': API_KEY }
});
const data = await res.json();
console.log(data);
```

Notes:
- Jika menerima 401, periksa API key di log server atau `.env`.
- Untuk request berkecepatan tinggi, perhatikan rate limit dan header `Retry-After`.

---

## Docker
Quick start:
```bash
# Buat .env berisi DORAKULA_API_KEY dan OLLAMA keys jika perlu
docker-compose up -d
docker-compose logs -f dorakula
# Cek health
curl http://127.0.0.1:9093/api/health
```
Stop:
```bash
docker-compose down
```

---

## Testing
- Jalankan server (diperlukan oleh beberapa test)
- Jalankan test suite:
```bash
pytest tests/ -v -k "not rate_limit"
# Expected: 88 passed (contoh)
```

---

## Struktur Proyek (singkat)
```
dorakula/
├─ dorakula_server.py
├─ core/
├─ agents/
├─ advanced/
├─ tests/
├─ Dockerfile
├─ docker-compose.yml
└─ README.md
```

---

## Roadmap & Legal
- 7 Advanced Modules: WAF Bypass AI, LLM Security, Cloud Auditor, GraphQL, Supply Chain, WebSocket Fuzzer, Auto-Reporter

Gunakan hanya untuk pengujian berizin. Pelanggaran hukum menjadi tanggung jawab pengguna.

---

## Lisensi & Bantuan
- Lisensi: MIT — lihat file LICENSE
- Laporan bug / fitur: https://github.com/dorakula/dorakula/issues
- Dokumentasi lanjutan: ARCHITECTURE.md · CONTRIBUTING.md
