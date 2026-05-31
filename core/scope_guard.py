#!/usr/bin/env python3
"""Dorakula Scope Guard
Target whitelist validation - what HexStrike DOES NOT HAVE
Prevents scanning unauthorized targets.
"""
import ipaddress
import re
import logging
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class ScopeGuard:
    """Validate targets against allowed scope rules"""
    
    def __init__(self, allowed_targets: List[str] = None):
        self.allowed_domains: Set[str] = set()
        self.allowed_ips: Set[ipaddress._BaseNetwork] = set()
        self.allowed_patterns: List[re.Pattern] = []
        self.violations: List[Dict[str, Any]] = []
        
        if allowed_targets:
            for target in allowed_targets:
                self.add_target(target)
    
    def add_target(self, target: str):
        """Add a target to the allowed scope"""
        target = target.strip().lower()
        # Try as CIDR/IP range
        try:
            if '/' in target:
                self.allowed_ips.add(ipaddress.ip_network(target, strict=False))
            else:
                self.allowed_ips.add(ipaddress.ip_network(target + '/32', strict=False))
            return
        except ValueError:
            pass
        # Store as domain pattern
        self.allowed_domains.add(target)
        pattern = re.compile(r'(^|\.)' + re.escape(target) + r'$', re.IGNORECASE)
        self.allowed_patterns.append(pattern)
    
    def is_allowed(self, target: str) -> bool:
        """Check if a target is within allowed scope"""
        if not self.allowed_domains and not self.allowed_ips and not self.allowed_patterns:
            return True  # No restrictions configured
        
        target = target.strip()
        target_lower = target.lower()
        
        # Check domain patterns
        for pattern in self.allowed_patterns:
            if pattern.search(target_lower):
                return True
        
        # Check exact domain match
        for domain in self.allowed_domains:
            if target_lower == domain or target_lower.endswith('.' + domain):
                return True
        
        # Check IP
        try:
            addr = ipaddress.ip_address(target)
            for net in self.allowed_ips:
                if addr in net:
                    return True
        except ValueError:
            pass
        
        # Check URL
        try:
            parsed = urlparse(target)
            if parsed.hostname:
                return self.is_allowed(parsed.hostname)
        except Exception:
            pass
        
        return False
    
    def validate_action(self, action: Dict[str, Any]) -> bool:
        """Validate an action against scope rules"""
        target = action.get('target', action.get('host', ''))
        if not target:
            return True  # No target specified
        
        if self.is_allowed(target):
            return True
        
        violation = {
            'target': target,
            'action': action.get('tool', 'unknown'),
            'timestamp': __import__('time').time()
        }
        self.violations.append(violation)
        logger.warning('SCOPE VIOLATION: %s attempted on %s', action.get('tool', 'unknown'), target)
        return False
    
    def get_violations(self) -> List[Dict[str, Any]]:
        return self.violations.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'allowed_domains': len(self.allowed_domains),
            'allowed_ips': len(self.allowed_ips),
            'allowed_patterns': len(self.allowed_patterns),
            'total_violations': len(self.violations),
            'restrictions_active': bool(self.allowed_domains or self.allowed_ips or self.allowed_patterns)
        }
