#!/usr/bin/env python3
"""Dorakula Configuration Manager - Multi-Provider AI Support
Supports Ollama Cloud, NVIDIA, Puter.js with automatic key rotation.
Secure configuration loading from .env file.
"""
import os
import json
import logging
import secrets
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


def _load_env_file(env_path: str) -> Dict[str, str]:
    """Load environment variables from .env file securely."""
    env_vars = {}
    if os.path.exists(env_path):
        # Check file permissions (should be 600)
        file_stat = os.stat(env_path)
        if file_stat.st_mode & 0o777 != 0o600:
            logger.warning(f".env file has insecure permissions: {oct(file_stat.st_mode)}")
        
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, value = line.partition('=')
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    # Handle variable substitution like ${VAR}
                    if value.startswith('${') and value.endswith('}'):
                        ref_var = value[2:-1]
                        value = env_vars.get(ref_var, os.environ.get(ref_var, ''))
                    env_vars[key] = value
    return env_vars


def _get_random_key(env_vars: Dict[str, str], prefix: str) -> Optional[str]:
    """Get a random API key from a pool of keys with given prefix."""
    keys = []
    i = 1
    while True:
        key_name = f"{prefix}_{i}"
        if key_name in env_vars:
            keys.append(env_vars[key_name])
            i += 1
        else:
            # Try without number suffix for single key
            if i == 1 and prefix in env_vars:
                keys.append(env_vars[prefix])
            break
    
    if keys:
        return secrets.choice(keys)
    return None


@dataclass
class DorakulaConfig:
    """Central configuration for Dorakula - Multi-Provider AI with Auto Key Rotation"""
    host: str = '127.0.0.1'
    port: int = 8888
    debug: bool = False
    mcp_port: int = 8766
    
    # AI Providers Configuration
    # Ollama Cloud
    ollama_url: str = 'https://ollama.ai'
    ollama_model: str = 'qwen2.5-coder:7b'
    ollama_api_key: Optional[str] = None
    
    # NVIDIA NIM (Backup)
    nvidia_api_key: Optional[str] = None
    nvidia_base_url: str = 'https://integrate.api.nvidia.com/v1'
    
    # Puter.js (Optional)
    puter_token: Optional[str] = None
    
    # Active provider selection
    ai_provider: str = 'ollama'  # 'ollama', 'nvidia', 'puter'
    
    # Auth - Generated randomly if not set
    dorakula_api_key: str = field(default_factory=lambda: '')
    hmac_secret: str = field(default_factory=lambda: '')
    
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
        
        # Determine env file path
        if not env_path:
            env_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                '.env'
            )
        
        # Load .env file
        env_vars = _load_env_file(env_path)
        
        # Merge with system environment (system env takes precedence)
        for key, value in os.environ.items():
            env_vars[key] = value
        
        # Server config
        config.host = env_vars.get('HOST', env_vars.get('DORAKULA_HOST', config.host))
        config.port = int(env_vars.get('PORT', env_vars.get('DORAKULA_PORT', config.port)))
        config.debug = env_vars.get('DEBUG', env_vars.get('DORAKULA_DEBUG', 'false')).lower() in ('true', '1', 'yes')
        config.mcp_port = int(env_vars.get('MCP_PORT', env_vars.get('DORAKULA_MCP_PORT', config.mcp_port)))
        
        # AI Provider Keys - Auto rotation from pools
        config.ollama_api_key = _get_random_key(env_vars, 'OLLAMA_API_KEY') or env_vars.get('ACTIVE_OLLAMA_KEY')
        config.nvidia_api_key = _get_random_key(env_vars, 'NVIDIA_API_KEY') or env_vars.get('ACTIVE_NVIDIA_KEY')
        config.puter_token = _get_random_key(env_vars, 'PUTER_TOKEN')
        
        # AI URLs and Models
        config.ollama_url = env_vars.get('OLLAMA_URL', env_vars.get('DORAKULA_OLLAMA_URL', config.ollama_url))
        config.ollama_model = env_vars.get('OLLAMA_MODEL', env_vars.get('DORAKULA_OLLAMA_MODEL', config.ollama_model))
        config.ai_provider = env_vars.get('AI_PROVIDER', 'ollama').lower()
        
        # Auth - Generate random secrets if not provided
        config.dorakula_api_key = env_vars.get('SECRET_KEY', env_vars.get('DORAKULA_API_KEY', config.dorakula_api_key))
        if not config.dorakula_api_key:
            config.dorakula_api_key = secrets.token_hex(32)
            logger.info("Generated random SECRET_KEY for security")
        
        config.hmac_secret = env_vars.get('HMAC_SECRET', env_vars.get('DORAKULA_HMAC_SECRET', config.hmac_secret))
        if not config.hmac_secret:
            config.hmac_secret = secrets.token_hex(32)
            logger.info("Generated random HMAC_SECRET for security")
        
        # Sandbox
        config.sandbox_enabled = env_vars.get('SANDBOX_ENABLED', env_vars.get('DORAKULA_SANDBOX', 'true')).lower() in ('true', '1', 'yes')
        config.sandbox_timeout = int(env_vars.get('SANDBOX_TIMEOUT', env_vars.get('DORAKULA_SANDBOX_TIMEOUT', config.sandbox_timeout)))
        config.sandbox_dir = env_vars.get('SANDBOX_DIR', env_vars.get('DORAKULA_SANDBOX_DIR', config.sandbox_dir))
        
        # Scope
        config.scope_file = env_vars.get('SCOPE_FILE', env_vars.get('DORAKULA_SCOPE_FILE', config.scope_file))
        
        # Audit
        config.audit_dir = env_vars.get('AUDIT_DIR', env_vars.get('DORAKULA_AUDIT_DIR', config.audit_dir))
        config.audit_enabled = env_vars.get('AUDIT_ENABLED', env_vars.get('DORAKULA_AUDIT_ENABLED', 'true')).lower() in ('true', '1', 'yes')
        
        # Sovereign
        config.sovereign_mode = env_vars.get('SOVEREIGN_MODE', env_vars.get('DORAKULA_SOVEREIGN', 'true')).lower() in ('true', '1', 'yes')
        
        # Cache
        config.cache_max_size = int(env_vars.get('CACHE_MAX_SIZE', env_vars.get('DORAKULA_CACHE_MAX_SIZE', config.cache_max_size)))
        config.cache_ttl = int(env_vars.get('CACHE_TTL', env_vars.get('DORAKULA_CACHE_TTL', config.cache_ttl)))
        
        # Process Management
        config.max_concurrent = int(env_vars.get('MAX_CONCURRENT', env_vars.get('DORAKULA_MAX_CONCURRENT', config.max_concurrent)))
        
        # Cloudflared
        config.cloudflared_tunnel = env_vars.get('CLOUDFLARED_TUNNEL', env_vars.get('DORAKULA_CLOUDFLARED', 'false')).lower() in ('true', '1', 'yes')
        
        # Logging
        config.log_level = env_vars.get('LOG_LEVEL', env_vars.get('DORAKULA_LOG_LEVEL', config.log_level))
        
        # Allowed targets
        targets_str = env_vars.get('ALLOWED_TARGETS', env_vars.get('DORAKULA_ALLOWED_TARGETS', ''))
        if targets_str:
            config.allowed_targets = [t.strip() for t in targets_str.split(',') if t.strip()]
        
        # Ensure directories exist
        for d in [config.audit_dir, config.sandbox_dir]:
            os.makedirs(d, exist_ok=True)
        
        logger.info(f"Configuration loaded from {env_path}")
        logger.info(f"AI Provider: {config.ai_provider}")
        if config.ollama_api_key:
            logger.info("Ollama API key loaded (rotated)")
        if config.nvidia_api_key:
            logger.info("NVIDIA API key loaded (backup)")
        
        return config

    def to_dict(self) -> Dict[str, Any]:
        return {
            'host': self.host, 
            'port': self.port, 
            'debug': self.debug,
            'mcp_port': self.mcp_port,
            'ai_provider': self.ai_provider,
            'ollama_model': self.ollama_model,
            'sandbox_enabled': self.sandbox_enabled,
            'sovereign_mode': self.sovereign_mode,
            'audit_enabled': self.audit_enabled,
            'cloudflared_tunnel': self.cloudflared_tunnel,
            'allowed_targets_count': len(self.allowed_targets),
            'has_ollama_key': bool(self.ollama_api_key),
            'has_nvidia_key': bool(self.nvidia_api_key),
            'has_puter_token': bool(self.puter_token),
            'auth_configured': bool(self.dorakula_api_key and self.hmac_secret),
        }
