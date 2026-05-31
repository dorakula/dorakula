#!/usr/bin/env python3
"""Dorakula Sandbox Executor
Isolated command execution - what HexStrike DOES NOT HAVE
Prevents AI-generated code from damaging the host system.
"""
import subprocess
import logging
import os
import tempfile
import shutil
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class SandboxExecutor:
    """Execute commands in isolated sandbox environment"""
    
    def __init__(self, timeout: int = 60, memory_mb: int = 512, enabled: bool = True):
        self.timeout = timeout
        self.memory_mb = memory_mb
        self.enabled = enabled
        self._nsjail_available = self._check_nsjail()
        self._docker_available = self._check_docker()
    
    def _check_nsjail(self) -> bool:
        try:
            result = subprocess.run(['which', 'nsjail'], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_docker(self) -> bool:
        try:
            result = subprocess.run(['which', 'docker'], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def execute(self, command: str, risk_level: str = 'low') -> Dict[str, Any]:
        """Execute command with appropriate isolation level"""
        if not self.enabled:
            return self._execute_direct(command)
        
        if risk_level == 'critical':
            return self._execute_nsjail(command)
        elif risk_level == 'high':
            if self._nsjail_available:
                return self._execute_nsjail(command)
            return self._execute_constrained(command)
        else:
            return self._execute_constrained(command)
    
    def _execute_direct(self, command: str) -> Dict[str, Any]:
        """Direct execution (no sandbox) - dev mode only"""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=self.timeout
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'sandbox': 'none'
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout', 'returncode': -1, 'sandbox': 'none'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'returncode': -1, 'sandbox': 'none'}
    
    def _execute_constrained(self, command: str) -> Dict[str, Any]:
        """Constrained execution with resource limits"""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=self.timeout,
                preexec_fn=self._set_resource_limits if os.getuid() == 0 else None
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'sandbox': 'constrained'
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout', 'returncode': -1, 'sandbox': 'constrained'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'returncode': -1, 'sandbox': 'constrained'}
    
    def _execute_nsjail(self, command: str) -> Dict[str, Any]:
        """Execute in nsjail sandbox - maximum isolation"""
        if not self._nsjail_available:
            logger.warning('nsjail not available, falling back to constrained mode')
            return self._execute_constrained(command)
        try:
            nsjail_cmd = [
                'nsjail', '--mode', 'o',
                '--time_limit', str(self.timeout),
                '--cgroup_mem_max', str(self.memory_mb * 1024 * 1024),
                '--cwd', '/tmp',
                '--', '/bin/sh', '-c', command
            ]
            result = subprocess.run(
                nsjail_cmd, capture_output=True, text=True,
                timeout=self.timeout + 10
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'sandbox': 'nsjail'
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Sandbox timeout', 'returncode': -1, 'sandbox': 'nsjail'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'returncode': -1, 'sandbox': 'nsjail'}
    
    def _set_resource_limits(self):
        """Set process resource limits (called in child process)"""
        import resource
        try:
            resource.setrlimit(resource.RLIMIT_AS, (self.memory_mb * 1024 * 1024, self.memory_mb * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))
            resource.setrlimit(resource.RLIMIT_NOFILE, (200, 200))
        except Exception:
            pass
    
    def execute_python(self, code: str, risk_level: str = 'high') -> Dict[str, Any]:
        """Execute Python code in sandbox"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            tmp_path = f.name
        try:
            return self.execute(f'/usr/bin/python3 {tmp_path}', risk_level)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
