#!/usr/bin/env python3
"""Dorakula Authentication Manager
API Key + HMAC signing with Fail-Closed Security
Secure authentication with constant-time comparison, rate limiting, and audit logging.
"""
import hashlib
import hmac
import time
import logging
import secrets
import threading
import json
import os
from typing import Optional, Dict, Any, List
from functools import wraps
from datetime import datetime, timedelta
from collections import OrderedDict

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter with per-client tracking"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clients: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed under rate limit"""
        now = time.time()
        with self._lock:
            if client_id not in self._clients:
                self._clients[client_id] = []
            
            # Remove old timestamps outside window
            self._clients[client_id] = [
                ts for ts in self._clients[client_id] 
                if now - ts < self.window_seconds
            ]
            
            if len(self._clients[client_id]) >= self.max_requests:
                return False
            
            self._clients[client_id].append(now)
            return True
    
    def get_remaining(self, client_id: str) -> int:
        """Get remaining requests in current window"""
        now = time.time()
        with self._lock:
            if client_id not in self._clients:
                return self.max_requests
            
            valid_requests = [
                ts for ts in self._clients[client_id] 
                if now - ts < self.window_seconds
            ]
            return max(0, self.max_requests - len(valid_requests))


class AuthManager:
    """Authentication and request verification with fail-closed security"""
    
    def __init__(self, api_key: str = '', hmac_secret: str = ''):
        # FAIL-CLOSED: If no key provided, generate random one (no open mode)
        self.api_key = api_key if api_key else secrets.token_hex(32)
        self.hmac_secret = hmac_secret if hmac_secret else secrets.token_hex(32)
        
        self._request_timestamps: Dict[str, float] = {}
        self._rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
        self._audit_log: OrderedDict = OrderedDict(maxlen=1000)
        self._lock = threading.Lock()
        
        logger.info("AuthManager initialized with fail-closed security")
    
    def verify_api_key(self, provided_key: str) -> bool:
        """Verify API key using constant-time comparison - FAIL-CLOSED"""
        # FAIL-CLOSED: Always require valid key, no open mode
        if not provided_key:
            logger.warning("Authentication attempt with empty API key")
            self._log_auth_attempt(False, "empty_key")
            return False
        
        if not self.api_key:
            logger.error("No API key configured - rejecting all requests")
            self._log_auth_attempt(False, "no_configured_key")
            return False
        
        # Use constant-time comparison to prevent timing attacks
        is_valid = secrets.compare_digest(provided_key, self.api_key)
        
        if not is_valid:
            logger.warning(f"Invalid API key attempt: {provided_key[:8]}...")
            self._log_auth_attempt(False, "invalid_key")
        
        return is_valid
    
    def _log_auth_attempt(self, success: bool, reason: str, client_id: str = ""):
        """Log authentication attempt for audit"""
        with self._lock:
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'success': success,
                'reason': reason,
                'client_id': client_id or 'unknown'
            }
            self._audit_log[entry['timestamp']] = entry
    
    def sign_request(self, payload: str, timestamp: float) -> str:
        """Create HMAC-SHA256 signature for request"""
        message = f"{payload}:{int(timestamp)}"
        return hmac.new(
            self.hmac_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def verify_signature(self, payload: str, timestamp: float, signature: str) -> bool:
        """Verify HMAC-SHA256 signature with strict validation"""
        # Check timestamp validity (5 minute window)
        now = time.time()
        if abs(now - timestamp) > 300:
            logger.warning(f'Request timestamp expired: {timestamp}')
            return False
        
        expected = self.sign_request(payload, timestamp)
        return secrets.compare_digest(expected, signature)
    
    def check_rate_limit(self, client_id: str) -> bool:
        """Check rate limiting per client"""
        return self._rate_limiter.is_allowed(client_id)
    
    def get_rate_limit_remaining(self, client_id: str) -> int:
        """Get remaining requests for client"""
        return self._rate_limiter.get_remaining(client_id)
    
    def require_auth(self, request_headers: Dict[str, str], client_ip: str = "") -> Dict[str, Any]:
        """Validate authentication from request headers with comprehensive checks"""
        result = {
            'authenticated': False, 
            'error': '',
            'rate_limit_remaining': 0
        }
        
        client_id = client_ip or request_headers.get('X-Forwarded-For', 'unknown')
        
        # Check rate limit first
        if not self.check_rate_limit(client_id):
            result['error'] = 'Rate limit exceeded'
            logger.warning(f"Rate limit exceeded for {client_id}")
            self._log_auth_attempt(False, "rate_limit", client_id)
            return result
        
        result['rate_limit_remaining'] = self.get_rate_limit_remaining(client_id)
        
        # Verify API key
        api_key = request_headers.get('X-Dorakula-API-Key', '')
        if not self.verify_api_key(api_key):
            result['error'] = 'Invalid or missing API key'
            return result
        
        # Optional: Verify HMAC signature if provided
        signature = request_headers.get('X-Dorakula-Signature', '')
        timestamp_str = request_headers.get('X-Dorakula-Timestamp', '')
        
        if signature and timestamp_str:
            try:
                timestamp = float(timestamp_str)
                # Get payload from body hash if available
                body_hash = request_headers.get('X-Dorakula-Body-Hash', '')
                if body_hash:
                    if not self.verify_signature(body_hash, timestamp, signature):
                        result['error'] = 'Invalid signature'
                        self._log_auth_attempt(False, "invalid_signature", client_id)
                        return result
            except ValueError:
                result['error'] = 'Invalid timestamp format'
                return result
        
        result['authenticated'] = True
        self._log_auth_attempt(True, "success", client_id)
        return result
    
    def get_api_key_hint(self) -> str:
        """Return partial API key for identification"""
        if not self.api_key:
            return 'not-configured'
        return self.api_key[:8] + '...' + self.api_key[-4:]
    
    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Get recent authentication audit log"""
        with self._lock:
            items = list(self._audit_log.values())
            return items[-limit:]
    
    def rotate_api_key(self) -> str:
        """Generate new API key (for emergency rotation)"""
        old_key = self.api_key
        self.api_key = secrets.token_hex(32)
        logger.info("API key rotated")
        self._log_auth_attempt(True, "key_rotated")
        return self.api_key
