"""
Modern API & GraphQL Specialist Module
Focus: GraphQL Introspection, Batch Attacks, DoS via Deep Queries, gRPC Fuzzing
Author: Dorakula Security Team
"""

import requests
import json
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin
import re

# Konfigurasi Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GraphQLScanner:
    """
    Scanner khusus untuk mendeteksi kerentanan pada endpoint GraphQL.
    Mendeteksi: Introspection leakage, Batch attacks, DoS queries, Authorization bypass.
    """
    
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url
        self.session = requests.Session()
        self.headers = headers or {
            "User-Agent": "Dorakula-GQL-Scanner/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.session.headers.update(self.headers)
        self.timeout = 10
        self.vulnerabilities = []

    def _send_query(self, query: str, variables: Optional[Dict] = None) -> Tuple[Optional[Dict], float]:
        """Mengirim query GraphQL dan mengukur waktu respons."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        start_time = time.time()
        try:
            response = self.session.post(self.base_url, json=payload, timeout=self.timeout)
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                return response.json(), elapsed
            else:
                logger.warning(f"Non-200 status code: {response.status_code}")
                return None, elapsed
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None, time.time() - start_time

    def check_introspection(self) -> Dict[str, Any]:
        """
        Memeriksa apakah Introspection Query diaktifkan.
        Ini bisa membocorkan seluruh skema API.
        """
        logger.info("Checking GraphQL Introspection...")
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              kind
              name
              fields { name }
            }
          }
        }
        """
        
        result, elapsed = self._send_query(introspection_query)
        
        vuln_report = {
            "type": "GraphQL Introspection Enabled",
            "severity": "Medium",
            "found": False,
            "details": "",
            "response_time": elapsed
        }

        if result and "data" in result and "__schema" in result.get("data", {}):
            vuln_report["found"] = True
            vuln_report["severity"] = "High"
            vuln_report["details"] = "Introspection is enabled. Full schema exposed."
            self.vulnerabilities.append(vuln_report)
            logger.warning("[VULN] GraphQL Introspection is ENABLED!")
        else:
            logger.info("Introspection seems disabled or protected.")
            
        return vuln_report

    def check_batch_attack(self) -> Dict[str, Any]:
        """
        Menguji kerentanan Batch Attack (mengirim banyak operasi dalam satu request).
        Bisa digunakan untuk bypass rate limiting atau brute force.
        """
        logger.info("Testing GraphQL Batch Attack...")
        
        # Membuat 10 query identik dalam satu request
        batch_payload = []
        test_query = "{ __typename }"
        for _ in range(10):
            batch_payload.append({"query": test_query})
        
        start_time = time.time()
        try:
            response = self.session.post(self.base_url, json=batch_payload, timeout=self.timeout)
            elapsed = time.time() - start_time
            
            vuln_report = {
                "type": "GraphQL Batch Attack Possible",
                "severity": "Medium",
                "found": False,
                "details": "",
                "response_time": elapsed
            }

            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) == 10:
                        vuln_report["found"] = True
                        vuln_report["details"] = "Server processed 10 operations in a single request without rejection."
                        self.vulnerabilities.append(vuln_report)
                        logger.warning("[VULN] GraphQL Batch Attack is possible (No batching limit detected).")
                except json.JSONDecodeError:
                    pass
            return vuln_report
        except Exception as e:
            logger.error(f"Batch attack test failed: {e}")
            return {"error": str(e)}

    def check_dos_deep_query(self) -> Dict[str, Any]:
        """
        Menguji kerentanan DoS melalui query bersarang (Deep Recursion).
        Query yang terlalu dalam dapat membebani server.
        """
        logger.info("Testing GraphQL DoS via Deep Query...")
        
        # Query bersarang yang mencoba mengambil relasi secara rekursif
        # Catatan: Ini disimulasikan dengan depth terbatas untuk keamanan testing
        deep_query = """
        query {
          user {
            friends {
              friends {
                friends {
                  friends {
                    friends {
                      id
                      name
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        result, elapsed = self._send_query(deep_query)
        
        vuln_report = {
            "type": "GraphQL DoS (Deep Query)",
            "severity": "High",
            "found": False,
            "details": "",
            "response_time": elapsed
        }

        if elapsed > 5.0: # Jika respons > 5 detik, indikasi beban berat
            vuln_report["found"] = True
            vuln_report["details"] = f"Query caused significant delay ({elapsed:.2f}s). Potential DoS vector."
            self.vulnerabilities.append(vuln_report)
            logger.warning(f"[VULN] Deep query caused latency: {elapsed:.2f}s")
        elif result and "errors" in result:
            errors = result.get("errors", [])
            if any("depth" in str(e).lower() or "complexity" in str(e).lower() for e in errors):
                vuln_report["details"] = "Server has depth/complexity protection enabled."
                logger.info("Server protects against deep queries.")
        
        return vuln_report

    def check_alias_overloading(self) -> Dict[str, Any]:
        """
        Menguji Alias Overloading. Penyerang bisa membuat banyak field alias
        untuk membebani resolver backend.
        """
        logger.info("Testing GraphQL Alias Overloading...")
        
        alias_query = "{ " + " ".join([f"a{i}: __typename" for i in range(50)]) + " }"
        
        result, elapsed = self._send_query(alias_query)
        
        vuln_report = {
            "type": "GraphQL Alias Overloading",
            "severity": "Medium",
            "found": False,
            "details": "",
            "response_time": elapsed
        }

        if result and "data" in result:
            data_keys = len(result["data"].keys())
            if data_keys >= 50:
                vuln_report["found"] = True
                vuln_report["details"] = f"Server processed {data_keys} aliases in one request."
                self.vulnerabilities.append(vuln_report)
                logger.warning("[VULN] Alias Overloading possible.")
        
        return vuln_report

    def run_full_scan(self) -> List[Dict[str, Any]]:
        """Menjalankan semua pemeriksaan GraphQL."""
        logger.info(f"Starting full GraphQL scan on {self.base_url}")
        self.vulnerabilities = []
        
        checks = [
            self.check_introspection,
            self.check_batch_attack,
            self.check_dos_deep_query,
            self.check_alias_overloading
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                logger.error(f"Check {check.__name__} failed: {e}")
                
        return self.vulnerabilities


class GRPCFuzzer:
    """
    Fuzzer sederhana untuk endpoint gRPC (memerlukan library grpcio untuk full implementation).
    Di sini kita simulasi deteksi endpoint dan fuzzing HTTP-based gRPC gateway.
    """
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.headers = {"Content-Type": "application/grpc-web-text"} # Simulasi header gRPC-web
        logger.info("gRPC Fuzzer initialized (HTTP Gateway Mode)")

    def detect_grpc_endpoint(self) -> bool:
        """Mendeteksi apakah URL kemungkinan adalah gRPC gateway."""
        # Biasanya gRPC web gateway merespons dengan konten tipe khusus atau error spesifik
        try:
            resp = self.session.options(self.base_url, timeout=5)
            if 'grpc' in resp.headers.get('Access-Control-Allow-Headers', '').lower():
                logger.info("Potential gRPC Web Gateway detected via CORS headers.")
                return True
        except Exception as e:
            logger.debug(f"gRPC detection error: {e}")
        return False

    def fuzz_method(self, methods: List[str]) -> List[Dict]:
        """Mencoba memanggil metode gRPC yang umum."""
        findings = []
        logger.info(f"Fuzzing {len(methods)} gRPC methods...")
        
        for method in methods:
            # Simulasi payload gRPC-web (base64 encoded protobuf kosong biasanya)
            # Ini hanya placeholder untuk logika fuzzing
            payload = "AAAAAAE=" 
            target = f"{self.base_url}/{method}"
            
            try:
                resp = self.session.post(target, data=payload, headers=self.headers, timeout=5)
                if resp.status_code not in [404, 405]:
                    findings.append({
                        "method": method,
                        "status": resp.status_code,
                        "note": "Unexpected response, might be valid endpoint"
                    })
                    logger.warning(f"Interesting response from {method}: {resp.status_code}")
            except Exception as e:
                continue
                
        return findings


def scan_api_target(target_url: str, api_type: str = "graphql") -> Dict[str, Any]:
    """
    Fungsi utama untuk memulai scan API berdasarkan tipe.
    """
    results = {
        "target": target_url,
        "type": api_type,
        "vulnerabilities": [],
        "status": "completed"
    }
    
    try:
        if api_type.lower() == "graphql":
            scanner = GraphQLScanner(target_url)
            results["vulnerabilities"] = scanner.run_full_scan()
        elif api_type.lower() == "grpc":
            fuzzer = GRPCFuzzer(target_url)
            if fuzzer.detect_grpc_endpoint():
                common_methods = ["UserService.Get", "AuthService.Login", "PaymentService.Charge"]
                results["vulnerabilities"] = fuzzer.fuzz_method(common_methods)
            else:
                logger.info("No gRPC endpoint detected.")
        else:
            logger.error(f"Unsupported API type: {api_type}")
            results["status"] = "error"
            
    except Exception as e:
        logger.error(f"Critical error during API scan: {e}")
        results["status"] = "failed"
        results["error"] = str(e)
        
    return results

if __name__ == "__main__":
    # Contoh penggunaan
    TARGET = "http://example.com/graphql"
    print(f"Scanning {TARGET}...")
    report = scan_api_target(TARGET, "graphql")
    print(json.dumps(report, indent=2))
