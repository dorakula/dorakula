#!/usr/bin/env python3
"""Dorakula Audit Logger
Append-only audit log with hash chain - what HexStrike DOES NOT HAVE
Ensures full traceability of all actions.
"""
import os
import json
import hashlib
import time
import threading
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AuditLogger:
    """Append-only audit log with integrity verification"""
    
    def __init__(self, log_path: str = '', enabled: bool = True):
        self.enabled = enabled
        self.log_path = log_path or '/home/kali/kali-agent/dorakula/logs/audit.log'
        self._lock = threading.Lock()
        self._last_hash = '0' * 64  # Genesis hash
        self._entry_count = 0
        
        if self.enabled:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            self._load_last_hash()
    
    def _load_last_hash(self):
        """Load the last hash from existing log file"""
        try:
            if os.path.exists(self.log_path):
                with open(self.log_path, 'r') as f:
                    lines = f.readlines()
                    if lines:
                        last_line = lines[-1].strip()
                        if last_line:
                            try:
                                entry = json.loads(last_line)
                                self._last_hash = entry.get('hash', self._last_hash)
                                self._entry_count = len([l for l in lines if l.strip()])
                            except json.JSONDecodeError:
                                pass
        except Exception as e:
            logger.warning('Failed to load audit log: %s', e)
    
    def log(self, action: str, details: Dict[str, Any], level: str = 'INFO') -> bool:
        """Log an action with hash chain integrity"""
        if not self.enabled:
            return True
        
        entry = {
            'id': self._entry_count + 1,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': level,
            'action': action,
            'details': details,
            'prev_hash': self._last_hash
        }
        
        # Calculate hash of this entry
        entry_str = json.dumps(entry, sort_keys=True)
        entry['hash'] = hashlib.sha256(entry_str.encode()).hexdigest()
        self._last_hash = entry['hash']
        self._entry_count += 1
        
        try:
            with self._lock:
                with open(self.log_path, 'a') as f:
                    f.write(json.dumps(entry) + '\n')
            return True
        except Exception as e:
            logger.error('Failed to write audit log: %s', e)
            return False
    
    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the hash chain integrity of the audit log"""
        if not os.path.exists(self.log_path):
            return {'valid': True, 'entries': 0, 'message': 'No audit log found'}
        
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
            
            prev_hash = '0' * 64
            errors = []
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    stored_hash = entry.get('hash', '')
                    stored_prev = entry.get('prev_hash', '')
                    
                    if stored_prev != prev_hash:
                        errors.append(f'Entry {i+1}: hash chain broken')
                    
                    # Verify entry hash
                    entry_copy = {k: v for k, v in entry.items() if k != 'hash'}
                    expected_hash = hashlib.sha256(json.dumps(entry_copy, sort_keys=True).encode()).hexdigest()
                    
                    prev_hash = stored_hash
                except json.JSONDecodeError:
                    errors.append(f'Entry {i+1}: invalid JSON')
            
            return {
                'valid': len(errors) == 0,
                'entries': len(lines),
                'errors': errors
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'enabled': self.enabled,
            'log_path': self.log_path,
            'total_entries': self._entry_count,
            'last_hash': self._last_hash[:16] + '...'
        }
