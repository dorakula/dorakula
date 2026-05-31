#!/usr/bin/env python3
"""Dorakula Authentication Manager
API Key + HMAC signing - what HexStrike DOES NOT HAVE
"""
import hashlib
import hmac
import time
import logging
import secrets
from typing import Optional, Dict, Any
from functools import wraps

logger = logging.getLogger(__name__)

class AuthManager:
    """Authentication and request verification"""
    
    def __init__(self, api_key: str = '', hmac_secret: str = 'change-me-in-production'):
        self.api_key = api_key or secrets.token_hex(32)
        self.hmac_secret = hmac_secret
        self._request_timestamps: Dict[str, float] = {}
        self._rate_limit_window = 60
        self._rate_limit_max = 100
    
    def verify_api_key(self, provided_key: str) -> bool:
        """Verify API key using constant-time comparison"""
        if not self.api_key:
            return True  # No key configured = open mode (dev only)
        return secrets.compare_digest(provided_key, self.api_key)
    
    def sign_request(self, payload: str, timestamp: float) -> str:
        """Create HMAC-SHA256 signature for request"""
        message = f"{payload}:{timestamp}"
        return hmac.new(
            self.hmac_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def verify_signature(self, payload: str, timestamp: float, signature: str) -> bool:
        """Verify HMAC-SHA256 signature"""
        expected = self.sign_request(payload, timestamp)
        if abs(time.time() - timestamp) > 300:  # 5 min window
            logger.warning('Request timestamp expired')
            return False
        return secrets.compare_digest(expected, signature)
    
    def check_rate_limit(self, client_id: str) -> bool:
        """Simple rate limiting per client"""
        now = time.time()
        last = self._request_timestamps.get(client_id, 0)
        if now - last < self._rate_limit_window / self._rate_limit_max:
            return False
        self._request_timestamps[client_id] = now
        return True
    
    def require_auth(self, request_headers: Dict[str, str]) -> Dict[str, Any]:
        """Validate authentication from request headers"""
        result = {'authenticated': False, 'error': ''}
        
        api_key = request_headers.get('X-Dorakula-API-Key', '')
        if not self.verify_api_key(api_key):
            result['error'] = 'Invalid API key'
            return result
        
        result['authenticated'] = True
        return result
    
    def get_api_key_hint(self) -> str:
        """Return partial API key for identification"""
        if not self.api_key:
            return 'not-configured'
        return self.api_key[:8] + '...' + self.api_key[-4:]
