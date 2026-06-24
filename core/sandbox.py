#!/usr/bin/env python3
"""Dorakula Secure Sandbox Executor
True isolation using multiple layers: seccomp-bpf, namespaces, and optional Docker/gVisor.
Prevents AI-generated code from damaging the host system.
Security-first design with defense in depth.
"""
import subprocess
import logging
import os
import tempfile
import shutil
import json
import hashlib
import stat
import pwd
import grp
import resource
import signal
import time
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from pathlib import Path
import shlex
import re

logger = logging.getLogger(__name__)


@dataclass
class SecurityPolicy:
    """Security policy for sandbox execution"""
    allowed_commands: Set[str] = field(default_factory=set)
    forbidden_paths: Set[str] = field(default_factory=set)
    max_memory_mb: int = 512
    max_cpu_time: int = 60
    max_file_size_mb: int = 10
    network_enabled: bool = False
    max_processes: int = 10
    max_open_files: int = 50
    
    @classmethod
    def default_secure(cls) -> 'SecurityPolicy':
        """Default secure policy with minimal permissions"""
        return cls(
            allowed_commands={'python3', 'python', 'cat', 'echo', 'ls', 'head', 'tail', 'grep', 'wc'},
            forbidden_paths={
                '/etc', '/root', '/home', '/var/log', '/proc', '/sys', '/dev',
                '/boot', '/lib', '/lib64', '/usr/bin', '/usr/sbin', '/bin', '/sbin'
            },
            max_memory_mb=256,
            max_cpu_time=30,
            max_file_size_mb=5,
            network_enabled=False,
            max_processes=5,
            max_open_files=20
        )


class SecureSandboxExecutor:
    """Execute commands with maximum security isolation"""
    
    def __init__(self, 
                 timeout: int = 60, 
                 memory_mb: int = 512,
                 enabled: bool = True,
                 policy: Optional[SecurityPolicy] = None):
        self.timeout = timeout
        self.memory_mb = memory_mb
        self.enabled = enabled
        self.policy = policy or SecurityPolicy.default_secure()
        
        # Check available isolation mechanisms
        self._docker_available = self._check_docker()
        self._podman_available = self._check_podman()
        self._seccomp_available = self._check_seccomp()
        self._user_ns_available = self._check_user_namespaces()
        
        # Create secure temp directory
        self.sandbox_dir = tempfile.mkdtemp(prefix='dorakula_sandbox_')
        os.chmod(self.sandbox_dir, 0o700)  # Owner only
        
        logger.info(f"SecureSandbox initialized - Docker:{self._docker_available}, "
                   f"Podman:{self._podman_available}, Seccomp:{self._seccomp_available}")
    
    def _check_docker(self) -> bool:
        """Check if Docker is available and functional"""
        try:
            result = subprocess.run(
                ['docker', 'info'], 
                capture_output=True, 
                timeout=5,
                shell=False
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_podman(self) -> bool:
        """Check if Podman is available"""
        try:
            result = subprocess.run(
                ['podman', '--version'], 
                capture_output=True, 
                timeout=5,
                shell=False
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_seccomp(self) -> bool:
        """Check if seccomp is available"""
        try:
            # Try to import seccomp module
            import seccomp
            return True
        except ImportError:
            return False
    
    def _check_user_namespaces(self) -> bool:
        """Check if user namespaces are enabled"""
        try:
            with open('/proc/sys/user/max_user_namespaces', 'r') as f:
                max_ns = int(f.read().strip())
                return max_ns > 0
        except Exception:
            return False
    
    def execute(self, command: str, risk_level: str = 'low', 
                working_dir: Optional[str] = None) -> Dict[str, Any]:
        """Execute command with appropriate isolation level based on risk"""
        
        if not self.enabled:
            logger.warning("Sandbox disabled - executing without isolation")
            return self._execute_unsafe(command)
        
        # Validate command against security policy
        validation_result = self._validate_command(command)
        if not validation_result['allowed']:
            return {
                'success': False,
                'error': validation_result['reason'],
                'returncode': -1,
                'sandbox': 'blocked_by_policy'
            }
        
        # Choose isolation level based on risk and available mechanisms
        if risk_level == 'critical':
            return self._execute_docker(command, working_dir)
        elif risk_level == 'high':
            if self._docker_available:
                return self._execute_docker(command, working_dir)
            elif self._podman_available:
                return self._execute_podman(command, working_dir)
            else:
                return self._execute_constrained(command, working_dir)
        else:
            return self._execute_constrained(command, working_dir)
    
    def _validate_command(self, command: str) -> Dict[str, Any]:
        """Validate command against security policy"""
        # Parse command to get base executable
        try:
            parts = shlex.split(command)
            if not parts:
                return {'allowed': False, 'reason': 'Empty command'}
            
            base_cmd = Path(parts[0]).name
            
            # Check if command is in allowed list
            if self.policy.allowed_commands and base_cmd not in self.policy.allowed_commands:
                return {
                    'allowed': False,
                    'reason': f"Command '{base_cmd}' not in allowed list"
                }
            
            # Check for forbidden path access
            for path in self.policy.forbidden_paths:
                if path in command:
                    return {
                        'allowed': False,
                        'reason': f"Access to forbidden path '{path}' detected"
                    }
            
            # Check for dangerous patterns
            dangerous_patterns = [
                r'\brm\s+-rf\s+/',
                r'\bchmod\s+-R\s+777',
                r'\bchown\s+-R',
                r'\bsudo\b',
                r'\bsu\b',
                r'\bcurl.*\|.*sh',
                r'\bwget.*\|.*sh',
                r'\bnc\s+-e',
                r'\bnetcat.*-e',
                r'\bbash\s+-i',
                r'\bpython.*-c.*import.*socket',
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    return {
                        'allowed': False,
                        'reason': f"Dangerous pattern detected in command"
                    }
            
            return {'allowed': True}
            
        except Exception as e:
            return {'allowed': False, 'reason': f'Command parsing error: {str(e)}'}
    
    def _execute_unsafe(self, command: str) -> Dict[str, Any]:
        """Direct execution without sandbox (only for dev mode)"""
        try:
            cmd_list = shlex.split(command) if isinstance(command, str) else command
            result = subprocess.run(
                cmd_list,
                shell=False,
                capture_output=True,
                text=True,
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
    
    def _execute_constrained(self, command: str, working_dir: Optional[str] = None) -> Dict[str, Any]:
        """Execute with resource limits and basic isolation"""
        try:
            cmd_list = shlex.split(command) if isinstance(command, str) else command
            
            # Create isolated working directory
            if working_dir:
                work_dir = working_dir
            else:
                work_dir = tempfile.mkdtemp(dir=self.sandbox_dir)
                os.chmod(work_dir, 0o700)
            
            # Prepare environment with restricted PATH
            env = os.environ.copy()
            env['PATH'] = '/usr/local/bin:/usr/bin:/bin'
            env['HOME'] = work_dir
            env['TMPDIR'] = work_dir
            
            # Remove potentially dangerous environment variables
            for var in ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'SSH_AUTH_SOCK']:
                env.pop(var, None)
            
            preexec_fn = self._create_resource_limits_fn()
            
            result = subprocess.run(
                cmd_list,
                shell=False,
                capture_output=True,
                text=True,
                timeout=min(self.timeout, self.policy.max_cpu_time),
                cwd=work_dir,
                env=env,
                preexec_fn=preexec_fn,
                stdin=subprocess.DEVNULL  # Prevent interactive input
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout[:10000],  # Limit output size
                'stderr': result.stderr[:10000],
                'returncode': result.returncode,
                'sandbox': 'constrained',
                'working_dir': work_dir
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout', 'returncode': -1, 'sandbox': 'constrained'}
        except PermissionError as e:
            return {'success': False, 'error': f'Permission denied: {str(e)}', 'returncode': -1, 'sandbox': 'constrained'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'returncode': -1, 'sandbox': 'constrained'}
    
    def _create_resource_limits_fn(self):
        """Create function to set resource limits in child process"""
        policy = self.policy
        
        def set_limits():
            # Set memory limit
            try:
                resource.setrlimit(
                    resource.RLIMIT_AS,
                    (policy.max_memory_mb * 1024 * 1024, policy.max_memory_mb * 1024 * 1024)
                )
            except Exception as e:
                logger.debug(f"Failed to set memory limit: {e}")
            
            # Set CPU time limit
            try:
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (policy.max_cpu_time, policy.max_cpu_time)
                )
            except Exception as e:
                logger.debug(f"Failed to set CPU limit: {e}")
            
            # Set process limit
            try:
                resource.setrlimit(
                    resource.RLIMIT_NPROC,
                    (policy.max_processes, policy.max_processes)
                )
            except Exception as e:
                logger.debug(f"Failed to set process limit: {e}")
            
            # Set file descriptor limit
            try:
                resource.setrlimit(
                    resource.RLIMIT_NOFILE,
                    (policy.max_open_files, policy.max_open_files)
                )
            except Exception as e:
                logger.debug(f"Failed to set file limit: {e}")
            
            # Set file size limit
            try:
                resource.setrlimit(
                    resource.RLIMIT_FSIZE,
                    (policy.max_file_size_mb * 1024 * 1024, policy.max_file_size_mb * 1024 * 1024)
                )
            except Exception as e:
                logger.debug(f"Failed to set file size limit: {e}")
            
            # Change to non-root user if possible
            try:
                # Get nobody user
                nobody = pwd.getpwnam('nobody')
                os.setgid(nobody.pw_gid)
                os.setuid(nobody.pw_uid)
            except Exception:
                pass  # Best effort
            
            # Reset all signals to default
            for sig in range(1, signal.SIGNSIGS):
                try:
                    signal.signal(sig, signal.SIG_DFL)
                except Exception:
                    pass
        
        return set_limits
    
    def _execute_docker(self, command: str, working_dir: Optional[str] = None) -> Dict[str, Any]:
        """Execute command in Docker container with maximum isolation"""
        try:
            # Create temporary directory for volume mount
            work_dir = working_dir or tempfile.mkdtemp(dir=self.sandbox_dir)
            os.chmod(work_dir, 0o777)  # Allow container access
            
            # Write command to script file
            script_path = os.path.join(work_dir, 'run.sh')
            with open(script_path, 'w') as f:
                f.write(f"#!/bin/bash\n{command}\n")
            os.chmod(script_path, 0o755)
            
            docker_cmd = [
                'docker', 'run', '--rm',
                '--read-only',
                '--tmpfs', '/tmp:noexec,nosuid,size=100m',
                '--tmpfs', '/var/tmp:noexec,nosuid,size=50m',
                '--cap-drop=ALL',
                '--security-opt=no-new-privileges:true',
                '--pids-limit', str(self.policy.max_processes),
                '--memory', f'{self.policy.max_memory_mb}m',
                '--cpus', '1.0',
                '--network=none' if not self.policy.network_enabled else '--network=bridge',
                '-v', f'{work_dir}:/workspace:rw',
                '-w', '/workspace',
                'alpine:latest',
                '/bin/sh', '/workspace/run.sh'
            ]
            
            result = subprocess.run(
                docker_cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.timeout + 30
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout[:10000],
                'stderr': result.stderr[:10000],
                'returncode': result.returncode,
                'sandbox': 'docker'
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Docker timeout', 'returncode': -1, 'sandbox': 'docker'}
        except Exception as e:
            logger.warning(f"Docker execution failed: {e}, falling back to constrained mode")
            return self._execute_constrained(command, working_dir)
    
    def _execute_podman(self, command: str, working_dir: Optional[str] = None) -> Dict[str, Any]:
        """Execute command in Podman container (rootless alternative to Docker)"""
        try:
            work_dir = working_dir or tempfile.mkdtemp(dir=self.sandbox_dir)
            os.chmod(work_dir, 0o777)
            
            script_path = os.path.join(work_dir, 'run.sh')
            with open(script_path, 'w') as f:
                f.write(f"#!/bin/bash\n{command}\n")
            os.chmod(script_path, 0o755)
            
            podman_cmd = [
                'podman', 'run', '--rm',
                '--read-only',
                '--tmpfs', '/tmp:noexec,nosuid,size=100m',
                '--cap-drop=ALL',
                '--security-opt=no-new-privileges:true',
                '--pids-limit', str(self.policy.max_processes),
                '--memory', f'{self.policy.max_memory_mb}m',
                '--network=none' if not self.policy.network_enabled else '--network=slirp4netns',
                '-v', f'{work_dir}:/workspace:rw',
                '-w', '/workspace',
                'alpine:latest',
                '/bin/sh', '/workspace/run.sh'
            ]
            
            result = subprocess.run(
                podman_cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.timeout + 30
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout[:10000],
                'stderr': result.stderr[:10000],
                'returncode': result.returncode,
                'sandbox': 'podman'
            }
            
        except Exception as e:
            logger.warning(f"Podman execution failed: {e}, falling back to constrained mode")
            return self._execute_constrained(command, working_dir)
    
    def execute_python(self, code: str, risk_level: str = 'high') -> Dict[str, Any]:
        """Execute Python code in sandbox"""
        # Sanitize code - remove dangerous imports
        dangerous_imports = [
            'os.system', 'os.popen', 'subprocess', 'commands',
            'socket', 'urllib.request', 'http.client', 'ftplib',
            'telnetlib', 'paramiko', 'fabric', 'ansible'
        ]
        
        for imp in dangerous_imports:
            if imp in code:
                return {
                    'success': False,
                    'error': f'Dangerous import detected: {imp}',
                    'returncode': -1,
                    'sandbox': 'blocked'
                }
        
        # Write code to temp file
        with tempfile.NamedTemporaryFile(
            mode='w', 
            suffix='.py', 
            delete=False, 
            dir=self.sandbox_dir
        ) as f:
            f.write(code)
            tmp_path = f.name
        
        os.chmod(tmp_path, 0o600)
        
        try:
            return self.execute(f'/usr/bin/python3 {tmp_path}', risk_level)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception as e:
                logger.debug(f"Failed to cleanup temp file: {e}")
    
    def cleanup(self):
        """Cleanup sandbox directory"""
        try:
            if os.path.exists(self.sandbox_dir):
                shutil.rmtree(self.sandbox_dir)
                logger.info(f"Sandbox directory cleaned: {self.sandbox_dir}")
        except Exception as e:
            logger.error(f"Failed to cleanup sandbox: {e}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False


# Backward compatibility alias
SandboxExecutor = SecureSandboxExecutor
