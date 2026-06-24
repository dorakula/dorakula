# DORAKULA v3.1.0 — Dockerfile
# Multi-stage: build nothing (pure Python), just install deps + run
FROM python:3.13-slim

# Install system dependencies for security tools
# (nmap, sqlmap, nuclei, etc. are expected to be installed separately
# or mounted from host — this image only provides the Python server)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY dorakula_server.py .
COPY core/ ./core/
COPY agents/ ./agents/
COPY advanced/ ./advanced/
COPY tools/ ./tools/
COPY tui/ ./tui/
COPY __init__.py .

# Copy config templates
COPY .env.example .
COPY dorakula-mcp.json .

# Expose ports: 9092 = MCP SSE, 9093 = REST API
EXPOSE 9092 9093

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9093/api/health', timeout=3)" || exit 1

# Run dorakula server
# API key must be provided via DORAKULA_API_KEY env var (no hardcoded default)
# Ollama keys via OLLAMA_API_KEY_1..5 env vars
CMD ["python", "dorakula_server.py", "--host", "0.0.0.0", "--port", "9092"]
