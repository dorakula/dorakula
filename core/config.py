#!/usr/bin/env python3
"""Dorakula Configuration Manager - OLLAMA ONLY
Clean config. No dead providers. No Puter.js. No Mistral.
"""
import os
import json
import logging
from typing import Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DorakulaConfig:
    """Central configuration for Dorakula - Ollama Sovereign Architecture"""
    host: str = '0.0.0.0'
    port: int = 8888
    debug: bool = False
    mcp_port: int = 8766
    # AI: OLLAMA (SOLE PROVIDER)
    ollama_url: str = 'http://localhost:11434'
    ollama_model: str = 'qwen2.5-coder:7b'
    # Auth
    dorakula_api_key: str = 'dorakula-superkey-2026'
    hmac_secret: str = 'dorakula-hmac-secret-2026'
    # Sandbox
    sandbox_enabled: bool = True
    sandbox_timeout: int = 300
    sandbox_dir: str = '/tmp/dorakula_sandbox'
    # Scope
    scope_file: str = '/home/kali/kali-agent/dorakula/scope.json'
    allowed_targets: list = field(default_factory=list)
    # Audit
    audit_dir: str = '/home/kali/kali-agent/dorakula/audit_logs'
    audit_enabled: bool = True
    # Sovereign
    sovereign_mode: bool = True
    # Cache
    cache_max_size: int = 500
    cache_ttl: int = 3600
    # Process Management
    max_concurrent: int = 5
    # Cloudflared
    cloudflared_tunnel: bool = False
    # Logging
    log_level: str = 'INFO'

    @classmethod
    def from_env(cls, env_path: str = '') -> 'DorakulaConfig':
        config = cls()
        env_file = env_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'configs', 'dorakula.env'
        )
        env_vars = {}
        if os.path.exists(env_file):
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, _, value = line.partition('=')
                        env_vars[key.strip()] = value.strip().strip('"').strip("'")
        for key, value in os.environ.items():
            if key.startswith('DORAKULA_'):
                env_vars[key] = value

        config.host = env_vars.get('DORAKULA_HOST', config.host)
        config.port = int(env_vars.get('DORAKULA_PORT', config.port))
        config.debug = env_vars.get('DORAKULA_DEBUG', '').lower() in ('true', '1', 'yes')
        config.mcp_port = int(env_vars.get('DORAKULA_MCP_PORT', config.mcp_port))
        config.ollama_url = env_vars.get('DORAKULA_OLLAMA_URL', config.ollama_url)
        config.ollama_model = env_vars.get('DORAKULA_OLLAMA_MODEL', config.ollama_model)
        config.dorakula_api_key = env_vars.get('DORAKULA_API_KEY', config.dorakula_api_key)
        config.hmac_secret = env_vars.get('DORAKULA_HMAC_SECRET', config.hmac_secret)
        config.sandbox_enabled = env_vars.get('DORAKULA_SANDBOX', 'true').lower() in ('true', '1', 'yes')
        config.sandbox_timeout = int(env_vars.get('DORAKULA_SANDBOX_TIMEOUT', config.sandbox_timeout))
        config.sandbox_dir = env_vars.get('DORAKULA_SANDBOX_DIR', config.sandbox_dir)
        config.scope_file = env_vars.get('DORAKULA_SCOPE_FILE', config.scope_file)
        config.audit_dir = env_vars.get('DORAKULA_AUDIT_DIR', config.audit_dir)
        config.audit_enabled = env_vars.get('DORAKULA_AUDIT_ENABLED', 'true').lower() in ('true', '1', 'yes')
        config.sovereign_mode = env_vars.get('DORAKULA_SOVEREIGN', 'true').lower() in ('true', '1', 'yes')
        config.cache_max_size = int(env_vars.get('DORAKULA_CACHE_MAX_SIZE', config.cache_max_size))
        config.cache_ttl = int(env_vars.get('DORAKULA_CACHE_TTL', config.cache_ttl))
        config.max_concurrent = int(env_vars.get('DORAKULA_MAX_CONCURRENT', config.max_concurrent))
        config.cloudflared_tunnel = env_vars.get('DORAKULA_CLOUDFLARED', '').lower() in ('true', '1', 'yes')
        config.log_level = env_vars.get('DORAKULA_LOG_LEVEL', config.log_level)
        targets_str = env_vars.get('DORAKULA_ALLOWED_TARGETS', '')
        if targets_str:
            config.allowed_targets = [t.strip() for t in targets_str.split(',') if t.strip()]
        # Ensure dirs
        for d in [config.audit_dir, config.sandbox_dir]:
            os.makedirs(d, exist_ok=True)
        return config

    def to_dict(self) -> Dict[str, Any]:
        return {
            'host': self.host, 'port': self.port, 'debug': self.debug,
            'mcp_port': self.mcp_port,
            'ollama_url': self.ollama_url, 'ollama_model': self.ollama_model,
            'sandbox_enabled': self.sandbox_enabled,
            'sovereign_mode': self.sovereign_mode,
            'audit_enabled': self.audit_enabled,
            'cloudflared_tunnel': self.cloudflared_tunnel,
            'allowed_targets_count': len(self.allowed_targets),
            'provider': 'ollama-only',
        }
