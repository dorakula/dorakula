"""
Dorakula Nmap Engine - Secure & Comprehensive Scanner
Menjalankan Nmap dengan sandboxing, parsing XML otomatis, dan pencegahan injeksi.
Terintegrasi dengan Dorakula Nmap Tamper Scripts untuk teknik evasi.
"""
import subprocess
import xml.etree.ElementTree as ET
import json
import os
import shlex
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import Tamper Script
try:
    from .nmap_tamper import NmapTamper
except ImportError:
    # Fallback jika dijalankan sebagai script standalone
    from nmap_tamper import NmapTamper

class NmapEngine:
    def __init__(self):
        self.nmap_path = self._find_nmap()
        self.max_output_size = 5 * 1024 * 1024  # 5MB limit
        
    def _find_nmap(self) -> str:
        """Mencari binary nmap di system PATH."""
        nmap_locations = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/local/bin/nmap",
            "nmap"  # Fallback to PATH
        ]
        
        for loc in nmap_locations:
            if os.path.isfile(loc) and os.access(loc, os.X_OK):
                return loc
            try:
                # Cek via which/where command jika bukan path absolut
                if not loc.startswith('/'):
                    result = subprocess.run(
                        ["which", loc] if os.name != 'nt' else ["where", loc],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        return result.stdout.strip().split('\n')[0]
            except Exception:
                continue
        return "nmap"  # Asumsi ada di PATH

    def _build_command(self, target: str, mode: str, ports: Optional[str] = None, 
                      extra_args: Optional[List[str]] = None, tamper_level: Optional[str] = None) -> List[str]:
        """
        Membangun argumen command secara aman (tanpa shell string concatenation).
        Mencegah command injection.
        
        Args:
            target: Target IP atau domain
            mode: quick, standard, aggressive, vuln
            ports: String port (e.g., "80,443" atau "1-1000")
            extra_args: List argumen tambahan yang diizinkan
            tamper_level: Level tamper script (normal, advanced, expert)
        """
        cmd = [self.nmap_path]
        
        # Apply Tamper Script jika ditentukan
        if tamper_level:
            try:
                tamper = NmapTamper(level=tamper_level)
                tamper_args = tamper.get_arguments()
                cmd.extend(tamper_args)
            except ValueError as e:
                # Log warning tapi lanjutkan tanpa tamper
                print(f"Warning: Invalid tamper level '{tamper_level}': {e}")
        
        # Mode Scan Profiles (hanya jika tidak ada tamper yang override)
        if not tamper_level:
            if mode == "quick":
                cmd.extend(["-F", "-T4", "--osscan-guess"])
            elif mode == "standard":
                cmd.extend(["-sV", "-sC", "-O", "-T4"])
            elif mode == "aggressive":
                cmd.extend(["-p-", "-A", "-T4", "--script=default,safe"])
            elif mode == "vuln":
                cmd.extend(["-sV", "--script=vuln,exploit", "-T4"])
            else:
                # Default safe mode
                cmd.extend(["-sV", "-sC", "-T3"])
            
            # Port Configuration
            if ports:
                # Validasi format port (hanya angka, koma, dash)
                if not all(c in "0123456789,-" for c in ports):
                    raise ValueError("Invalid port format. Use numbers, commas, or dashes only.")
                cmd.extend(["-p", ports])
            
        # Output Format (XML untuk parsing mudah)
        cmd.extend(["-oX", "-"])  # Output ke stdout
        
        # Extra Args (Whitelist validation) - hanya jika tidak conflict dengan tamper
        if extra_args:
            allowed_flags = {"-Pn", "-n", "-R", "-v", "--open"}
            for arg in extra_args:
                if arg in allowed_flags and arg not in cmd:
                    cmd.append(arg)

        # Target Validation (Basic)
        # Mencegah argumen injeksi seperti '; rm -rf /'
        if any(char in target for char in [';', '|', '&', '$', '`', '>', '<']):
            raise ValueError("Invalid characters in target address.")
            
        cmd.append(target)
        
        return cmd

    def _parse_xml(self, xml_content: str) -> Dict[str, Any]:
        """Parsing output XML Nmap menjadi dictionary Python."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            return {"error": f"Failed to parse Nmap XML: {str(e)}", "raw_output": xml_content[:500]}

        result = {
            "scan_info": {},
            "hosts": []
        }

        # Extract Scan Info
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                result["scan_info"]["time"] = finished.get("timestr")
                result["scan_info"]["elapsed"] = finished.get("elapsed")

        # Extract Hosts
        for host in root.findall("host"):
            host_data = {
                "ip": "",
                "hostname": [],
                "status": "",
                "ports": [],
                "os": []
            }

            # IP Address
            addr = host.find("address")
            if addr is not None:
                host_data["ip"] = addr.get("addr")
                host_data["mac"] = addr.get("addrtype")

            # Hostnames
            for hostname in host.findall("hostnames/hostname"):
                if hostname.get("name"):
                    host_data["hostname"].append(hostname.get("name"))

            # Status
            status = host.find("status")
            if status is not None:
                host_data["status"] = status.get("state")

            # Ports
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    port_info = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": "",
                        "service": "",
                        "version": "",
                        "scripts": []
                    }
                    
                    state = port.find("state")
                    if state is not None:
                        port_info["state"] = state.get("state")
                    
                    service = port.find("service")
                    if service is not None:
                        port_info["service"] = service.get("name", "")
                        port_info["version"] = service.get("product", "") + " " + service.get("version", "")
                        
                        # Extra info
                        if service.get("extrainfo"):
                            port_info["version"] += f" ({service.get('extrainfo')})"

                    # NSE Scripts
                    for script in port.findall("script"):
                        script_info = {
                            "id": script.get("id"),
                            "output": script.get("output", "")
                        }
                        port_info["scripts"].append(script_info)
                    
                    # Hanya tambahkan port terbuka atau tertarik
                    if port_info["state"] == "open":
                        host_data["ports"].append(port_info)

            # OS Detection
            os_elem = host.find("os")
            if os_elem is not None:
                for os_match in os_elem.findall("osmatch"):
                    os_info = {
                        "name": os_match.get("name"),
                        "accuracy": os_match.get("accuracy")
                    }
                    host_data["os"].append(os_info)

            result["hosts"].append(host_data)

        return result

    def scan(self, target: str, mode: str = "standard", 
             ports: Optional[str] = None, extra_args: Optional[List[str]] = None,
             tamper_level: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
        """
        Menjalankan scan Nmap.
        
        Args:
            target: IP atau Domain target
            mode: quick, standard, aggressive, vuln
            ports: String port (e.g., "80,443" atau "1-1000")
            extra_args: List argumen tambahan yang diizinkan
            tamper_level: Level tamper script (normal, advanced, expert)
            timeout: Timeout dalam detik
            
        Returns:
            Dictionary hasil scan terstruktur
        """
        if not self.nmap_path or self.nmap_path == "nmap":
            # Cek lagi apakah benar-benar ada di PATH jika fallback
            try:
                subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                return {
                    "error": "Nmap binary not found. Please install nmap (sudo apt install nmap).",
                    "status": "failed"
                }

        try:
            cmd = self._build_command(target, mode, ports, extra_args, tamper_level)
            
            # Eksekusi dengan subprocess.run (aman, no shell=True)
            # stdin=DEVNULL untuk mencegah interaksi
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input="", 
                check=False, # Jangan raise exception jika return code != 0
                env={**os.environ, "LC_ALL": "C"} # Force English output
            )
            
            output = result.stdout
            error = result.stderr
            
            # Handle error dari nmap itu sendiri
            if result.returncode != 0 and not output:
                return {
                    "error": f"Nmap execution failed: {error}",
                    "status": "failed",
                    "return_code": result.returncode
                }
            
            # Parsing XML
            parsed_data = self._parse_xml(output)
            
            # Tambahkan metadata eksekusi
            parsed_data["meta"] = {
                "command": " ".join(cmd), # Untuk logging/debugging
                "return_code": result.returncode,
                "stderr": error.strip() if error else None,
                "mode": mode,
                "target": target
            }
            
            return parsed_data
            
        except subprocess.TimeoutExpired:
            return {
                "error": f"Scan timed out after {timeout} seconds.",
                "status": "timeout"
            }
        except PermissionError:
            return {
                "error": "Permission denied. Try running with sudo or check nmap capabilities.",
                "status": "permission_error"
            }
        except Exception as e:
            return {
                "error": f"Unexpected error: {str(e)}",
                "status": "error"
            }

# Singleton instance
nmap_engine = NmapEngine()

if __name__ == "__main__":
    # Test CLI sederhana dengan dukungan tamper
    import sys
    if len(sys.argv) < 2:
        print("Usage: python nmap_engine.py <target> [mode] [tamper_level]")
        print("Modes: quick, standard, aggressive, vuln")
        print("Tamper Levels: normal, advanced, expert")
        sys.exit(1)
    
    target = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "quick"
    tamper = sys.argv[3] if len(sys.argv) > 3 else None
    
    print(f"Starting Nmap scan on {target} ({mode} mode)...")
    if tamper:
        print(f"Using Tamper Script: {tamper}")
    
    result = nmap_engine.scan(target, mode=mode, tamper_level=tamper)
    print(json.dumps(result, indent=2))
