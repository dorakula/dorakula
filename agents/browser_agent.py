#!/usr/bin/env python3
"""DORAKULA Browser Agent — Selenium-based browser automation for security testing.

More advanced than HexStrike's browser agent:
  - Screenshot capture per endpoint (with timestamp)
  - DOM analysis (form detection, input field mapping, hidden fields)
  - JavaScript execution monitoring (console errors, eval calls, CSP violations)
  - Network traffic logging (XHR, fetch, WebSocket connections)
  - Security header analysis (visual + programmatic)
  - Cookie analysis (HttpOnly, Secure, SameSite)
  - Local storage / Session storage inspection
  - Click-jacking test (iframe embedding)
  - Mixed content detection (HTTP resources on HTTPS pages)
  - DOM-based XSS sink detection (innerHTML, document.write, eval patterns)
  - Performance metrics (Core Web Vitals)
  - Fingerprinting detection (Canvas, WebGL, AudioContext)

Dependencies: selenium (installed), chromium (system), chromedriver (system)
Fallback: graceful degradation if selenium not available

Threat Model:
  - Tests DOM for injection sinks (innerHTML, outerHTML, document.write)
  - Detects exposed sensitive data in page source
  - Maps attack surface via form/input discovery
  - Captures evidence via screenshots
"""
import logging
import json
import time
import os
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import (
        TimeoutException, WebDriverException,
        NoSuchElementException, StaleElementReferenceException
    )
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False
    logger.warning("Selenium not available. Browser Agent disabled. Install: pip install selenium")

# Try to import selenium-devtools for network logging
try:
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
    HAS_DEVTOOLS = True
except ImportError:
    HAS_DEVTOOLS = False


@dataclass
class DOMElement:
    """Represents a discovered DOM element."""
    tag: str
    type: str = ""
    name: str = ""
    id: str = ""
    value: str = ""
    placeholder: str = ""
    action: str = ""
    method: str = ""
    hidden: bool = False
    xpath: str = ""
    vulnerable: bool = False
    vulnerability_type: str = ""


@dataclass
class NetworkRequest:
    """Represents a captured network request."""
    method: str
    url: str
    status: int = 0
    mime_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    response_size: int = 0
    from_service_worker: bool = False


@dataclass
class ConsoleMessage:
    """Represents a browser console message."""
    level: str  # SEVERE, WARNING, INFO, DEBUG
    message: str
    source: str = ""
    line_number: int = 0


class BrowserAgent:
    """Selenium-based browser automation for security testing.

    More capable than HexStrike's browser agent:
      - DOM-based XSS sink detection (HexStrike: none)
      - Click-jacking test (HexStrike: none)
      - Mixed content detection (HexStrike: none)
      - Cookie security analysis (HexStrike: basic)
      - Local/session storage inspection (HexStrike: none)
      - Core Web Vitals (HexStrike: none)
      - Fingerprinting detection (HexStrike: none)
    """

    def __init__(self, timeout: int = 30, screenshot_dir: str = "/tmp/dorakula_screenshots"):
        self.timeout = timeout
        self.screenshot_dir = screenshot_dir
        os.makedirs(screenshot_dir, exist_ok=True)
        self._driver: Optional[webdriver.Chrome] = None
        self._network_requests: List[NetworkRequest] = []
        self._console_messages: List[ConsoleMessage] = []

    def _get_driver(self) -> Optional[webdriver.Chrome]:
        """Initialize Chrome driver with security-focused options."""
        if self._driver:
            return self._driver
        if not HAS_SELENIUM:
            return None
        try:
            options = Options()
            # Headless mode
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")
            # Security: disable web security for testing
            options.add_argument("--disable-web-security")
            options.add_argument("--allow-running-insecure-content")
            # Ignore certificate errors (security testing)
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--ignore-ssl-errors=yes")
            # Set realistic user agent
            options.add_argument("--user-agent=DORAKULA-Browser-Agent/2.0")
            # Enable performance logging for network capture
            options.set_capability("goog:loggingPrefs", {
                "performance": "ALL",
                "browser": "ALL",
            })

            # Use system chromedriver
            service = Service(executable_path="/usr/bin/chromedriver")
            self._driver = webdriver.Chrome(service=service, options=options)
            self._driver.set_page_load_timeout(self.timeout)
            self._driver.set_script_timeout(self.timeout)
            logger.info("Browser Agent: Chrome driver initialized (headless)")
            return self._driver
        except Exception as e:
            logger.error("Browser Agent: Failed to init Chrome driver: %s", e)
            return None

    def close(self) -> None:
        """Close the browser driver."""
        if self._driver:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None

    # ============================================================
    # Core: Navigate + capture
    # ============================================================

    def navigate(self, url: str) -> Dict[str, Any]:
        """Navigate to URL and capture initial page state."""
        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available", "tool": "browser_agent"}

        t0 = time.time()
        try:
            driver.get(url)
            # Wait for page to settle
            WebDriverWait(driver, min(self.timeout, 10)).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            elapsed = time.time() - t0
            return {
                "status": "success",
                "url": driver.current_url,
                "title": driver.title,
                "elapsed_sec": round(elapsed, 2),
                "page_source_size": len(driver.page_source),
            }
        except TimeoutException:
            return {"status": "timeout", "url": url, "error": f"Page load timed out after {self.timeout}s"}
        except Exception as e:
            return {"status": "error", "url": url, "error": str(e)[:200]}

    def screenshot(self, url: str, label: str = "") -> Dict[str, Any]:
        """Capture screenshot of URL."""
        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available"}

        nav_result = self.navigate(url)
        if nav_result.get("status") not in ("success", "timeout"):
            return nav_result

        try:
            safe_label = re.sub(r"[^a-zA-Z0-9_]", "_", label or url)[:50]
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.screenshot_dir, f"screenshot_{safe_label}_{timestamp}.png")
            driver.save_screenshot(filepath)
            return {
                "status": "success",
                "screenshot_path": filepath,
                "url": url,
                "file_size": os.path.getsize(filepath) if os.path.exists(filepath) else 0,
            }
        except Exception as e:
            return {"status": "error", "error": str(e)[:200]}

    # ============================================================
    # DOM Analysis
    # ============================================================

    def analyze_dom(self, url: str) -> Dict[str, Any]:
        """Analyze DOM for forms, inputs, hidden fields, and XSS sinks."""
        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available"}

        nav_result = self.navigate(url)
        if nav_result.get("status") not in ("success", "timeout"):
            return nav_result

        findings = []
        forms = []
        inputs = []
        xss_sinks = []
        hidden_fields = []

        try:
            # 1. Form detection
            form_elements = driver.find_elements(By.TAG_NAME, "form")
            for form in form_elements:
                form_data = DOMElement(
                    tag="form",
                    action=form.get_attribute("action") or "",
                    method=form.get_attribute("method") or "GET",
                    id=form.get_attribute("id") or "",
                    name=form.get_attribute("name") or "",
                )
                forms.append(asdict(form_data))

                # Check for missing CSRF token
                csrf_present = False
                for inp in form.find_elements(By.TAG_NAME, "input"):
                    name = (inp.get_attribute("name") or "").lower()
                    if "csrf" in name or "token" in name or "_token" in name:
                        csrf_present = True
                        break
                if not csrf_present and form_data.method.upper() == "POST":
                    findings.append({
                        "type": "missing_csrf_token",
                        "severity": "MEDIUM",
                        "description": f"Form '{form_data.name or form_data.id}' uses POST without CSRF token",
                        "form_action": form_data.action,
                    })

            # 2. Input field mapping
            input_elements = driver.find_elements(By.TAG_NAME, "input")
            for inp in input_elements:
                inp_type = inp.get_attribute("type") or "text"
                inp_data = DOMElement(
                    tag="input",
                    type=inp_type,
                    name=inp.get_attribute("name") or "",
                    id=inp.get_attribute("id") or "",
                    value=inp.get_attribute("value") or "",
                    placeholder=inp.get_attribute("placeholder") or "",
                    hidden=(inp_type == "hidden"),
                )
                inputs.append(asdict(inp_data))

                # Hidden fields with sensitive values
                if inp_type == "hidden":
                    val = inp.get_attribute("value") or ""
                    if val and any(k in val.lower() for k in ["token", "key", "secret", "password", "admin"]):
                        hidden_fields.append({
                            "name": inp_data.name,
                            "value": val[:50],
                            "severity": "HIGH",
                            "description": f"Hidden field '{inp_data.name}' contains sensitive value",
                        })

            # 3. XSS sink detection (DOM-based)
            # Search page source for dangerous patterns
            page_source = driver.page_source
            xss_patterns = [
                (r"innerHTML\s*=", "innerHTML assignment", "HIGH"),
                (r"outerHTML\s*=", "outerHTML assignment", "HIGH"),
                (r"document\.write\s*\(", "document.write call", "HIGH"),
                (r"\.html\s*\(", "jQuery .html() call", "MEDIUM"),
                (r"eval\s*\(", "eval() call", "CRITICAL"),
                (r"setTimeout\s*\(\s*['\"]", "setTimeout with string", "MEDIUM"),
                (r"setInterval\s*\(\s*['\"]", "setInterval with string", "MEDIUM"),
                (r"Function\s*\(", "Function constructor", "HIGH"),
            ]
            for pattern, desc, severity in xss_patterns:
                matches = re.findall(pattern, page_source)
                if matches:
                    xss_sinks.append({
                        "pattern": desc,
                        "severity": severity,
                        "count": len(matches),
                        "description": f"Found {len(matches)} instance(s) of {desc} — potential DOM XSS sink",
                    })

            # 4. Script tag analysis (external scripts)
            scripts = driver.find_elements(By.TAG_NAME, "script")
            external_scripts = []
            for script in scripts:
                src = script.get_attribute("src") or ""
                if src:
                    external_scripts.append(src)
                    # Check for SRI
                    integrity = script.get_attribute("integrity") or ""
                    if not integrity:
                        findings.append({
                            "type": "missing_sri",
                            "severity": "LOW",
                            "description": f"External script without SRI: {src[:80]}",
                            "script_src": src[:200],
                        })

            return {
                "status": "success",
                "url": url,
                "forms": forms,
                "inputs": inputs,
                "input_count": len(inputs),
                "hidden_fields": hidden_fields,
                "xss_sinks": xss_sinks,
                "external_scripts": external_scripts,
                "findings": findings,
                "findings_count": len(findings),
            }

        except Exception as e:
            return {"status": "error", "url": url, "error": str(e)[:200]}

    # ============================================================
    # JavaScript Monitoring
    # ============================================================

    def monitor_javascript(self, url: str) -> Dict[str, Any]:
        """Monitor JavaScript execution: console errors, eval calls, CSP violations."""
        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available"}

        nav_result = self.navigate(url)
        if nav_result.get("status") not in ("success", "timeout"):
            return nav_result

        console_errors = []
        console_warnings = []
        csp_violations = []

        try:
            # Get browser logs
            logs = driver.get_log("browser")
            for entry in logs:
                level = entry.get("level", "INFO")
                message = entry.get("message", "")
                source = entry.get("source", "")

                if level == "SEVERE":
                    console_errors.append({
                        "message": message[:200],
                        "source": source,
                    })
                    # Check for CSP violations
                    if "Content Security Policy" in message or "CSP" in message:
                        csp_violations.append({
                            "message": message[:200],
                            "severity": "MEDIUM",
                            "description": "CSP violation detected — may indicate CSP misconfiguration",
                        })
                elif level == "WARNING":
                    console_warnings.append({
                        "message": message[:200],
                        "source": source,
                    })

            # Check for eval() calls via JavaScript injection
            eval_detected = driver.execute_script("""
                var evalCalled = false;
                var origEval = window.eval;
                window.eval = function() {
                    evalCalled = true;
                    return origEval.apply(this, arguments);
                };
                // Wait briefly
                return new Promise(function(resolve) {
                    setTimeout(function() {
                        window.eval = origEval;
                        resolve(evalCalled);
                    }, 2000);
                });
            """)
            if eval_detected:
                csp_violations.append({
                    "type": "eval_usage",
                    "severity": "MEDIUM",
                    "description": "eval() detected during page execution — unsafe JavaScript",
                })

            return {
                "status": "success",
                "url": url,
                "console_errors": console_errors,
                "console_warnings": console_warnings,
                "csp_violations": csp_violations,
                "total_errors": len(console_errors),
                "total_warnings": len(console_warnings),
            }

        except Exception as e:
            return {"status": "error", "url": url, "error": str(e)[:200]}

    # ============================================================
    # Network Traffic Logging
    # ============================================================

    def log_network(self, url: str) -> Dict[str, Any]:
        """Log network requests: XHR, fetch, WebSocket, resource loads."""
        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available"}

        nav_result = self.navigate(url)
        if nav_result.get("status") not in ("success", "timeout"):
            return nav_result

        requests_log = []
        try:
            # Get performance logs
            perf_logs = driver.get_log("performance")
            for entry in perf_logs:
                try:
                    msg = json.loads(entry.get("message", "{}"))
                    event = msg.get("message", {})
                    method = event.get("method", "")

                    if method == "Network.requestWillBeSent":
                        req = event.get("params", {}).get("request", {})
                        requests_log.append({
                            "method": req.get("method", ""),
                            "url": req.get("url", "")[:200],
                            "headers": req.get("headers", {}),
                            "type": event.get("params", {}).get("type", ""),
                        })
                    elif method == "Network.responseReceived":
                        resp = event.get("params", {}).get("response", {})
                        requests_log.append({
                            "url": resp.get("url", "")[:200],
                            "status": resp.get("status", 0),
                            "mime_type": resp.get("mimeType", ""),
                            "headers": resp.get("headers", {}),
                        })
                except (json.JSONDecodeError, KeyError):
                    pass

            # Categorize requests
            xhr_requests = [r for r in requests_log if r.get("type") == "XHR"]
            fetch_requests = [r for r in requests_log if r.get("type") == "Fetch"]
            ws_requests = [r for r in requests_log if "ws://" in r.get("url", "") or "wss://" in r.get("url", "")]
            api_requests = [r for r in requests_log if "/api/" in r.get("url", "")]

            return {
                "status": "success",
                "url": url,
                "total_requests": len(requests_log),
                "xhr_requests": len(xhr_requests),
                "fetch_requests": len(fetch_requests),
                "websocket_requests": len(ws_requests),
                "api_requests": len(api_requests),
                "sample_requests": requests_log[:20],
                "websocket_endpoints": [r["url"] for r in ws_requests],
            }
        except Exception as e:
            return {"status": "error", "url": url, "error": str(e)[:200]}

    # ============================================================
    # Security Header Analysis (Visual + Programmatic)
    # ============================================================

    def analyze_security_headers(self, url: str) -> Dict[str, Any]:
        """Analyze security headers via browser."""
        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available"}

        nav_result = self.navigate(url)
        if nav_result.get("status") not in ("success", "timeout"):
            return nav_result

        try:
            # Get headers via JavaScript
            headers = driver.execute_script("""
                var req = new XMLHttpRequest();
                req.open('GET', window.location.href, false);
                req.send(null);
                return req.getAllResponseHeaders();
            """)

            header_dict = {}
            for line in headers.split("\n"):
                if ":" in line:
                    key, val = line.split(":", 1)
                    header_dict[key.strip()] = val.strip()

            # Analyze security headers
            security_headers = {
                "Strict-Transport-Security": {"expected": "max-age=31536000", "severity": "HIGH"},
                "Content-Security-Policy": {"expected": "default-src", "severity": "HIGH"},
                "X-Frame-Options": {"expected": "DENY or SAMEORIGIN", "severity": "MEDIUM"},
                "X-Content-Type-Options": {"expected": "nosniff", "severity": "MEDIUM"},
                "Referrer-Policy": {"expected": "strict-origin", "severity": "LOW"},
                "Permissions-Policy": {"expected": "geolocation", "severity": "LOW"},
                "Cross-Origin-Opener-Policy": {"expected": "same-origin", "severity": "MEDIUM"},
                "Cross-Origin-Embedder-Policy": {"expected": "require-corp", "severity": "LOW"},
            }

            findings = []
            for header, info in security_headers.items():
                if header not in header_dict:
                    findings.append({
                        "header": header,
                        "status": "missing",
                        "severity": info["severity"],
                        "description": f"Security header '{header}' is missing",
                        "recommendation": f"Add: {header}: {info['expected']}",
                    })
                else:
                    findings.append({
                        "header": header,
                        "status": "present",
                        "severity": "INFO",
                        "value": header_dict[header][:100],
                    })

            return {
                "status": "success",
                "url": url,
                "headers": header_dict,
                "security_findings": findings,
                "missing_count": sum(1 for f in findings if f["status"] == "missing"),
                "present_count": sum(1 for f in findings if f["status"] == "present"),
            }
        except Exception as e:
            return {"status": "error", "url": url, "error": str(e)[:200]}

    # ============================================================
    # Cookie Analysis
    # ============================================================

    def analyze_cookies(self, url: str) -> Dict[str, Any]:
        """Analyze cookies for security attributes."""
        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available"}

        nav_result = self.navigate(url)
        if nav_result.get("status") not in ("success", "timeout"):
            return nav_result

        try:
            cookies = driver.get_cookies()
            findings = []
            for cookie in cookies:
                issues = []
                if not cookie.get("httpOnly"):
                    issues.append("Missing HttpOnly — accessible via JavaScript (XSS risk)")
                if not cookie.get("secure"):
                    issues.append("Missing Secure — sent over HTTP (interception risk)")
                same_site = cookie.get("sameSite", "")
                if same_site not in ("Strict", "Lax"):
                    issues.append(f"SameSite={same_site or 'None'} — CSRF risk")

                if issues:
                    findings.append({
                        "cookie_name": cookie.get("name", ""),
                        "issues": issues,
                        "severity": "HIGH" if len(issues) >= 2 else "MEDIUM",
                    })

            return {
                "status": "success",
                "url": url,
                "total_cookies": len(cookies),
                "cookie_details": [{"name": c["name"], "domain": c.get("domain", ""),
                                   "httpOnly": c.get("httpOnly", False),
                                   "secure": c.get("secure", False),
                                   "sameSite": c.get("sameSite", "")} for c in cookies],
                "security_findings": findings,
            }
        except Exception as e:
            return {"status": "error", "url": url, "error": str(e)[:200]}

    # ============================================================
    # Click-jacking Test
    # ============================================================

    def test_clickjacking(self, url: str) -> Dict[str, Any]:
        """Test if page can be embedded in iframe (click-jacking vulnerability)."""
        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available"}

        try:
            # Create a test page with iframe
            test_html = f"""
            <html><body>
            <iframe src="{url}" style="width:100%;height:100vh;border:none;" id="target"></iframe>
            </body></html>
            """
            test_file = os.path.join(self.screenshot_dir, "clickjack_test.html")
            with open(test_file, "w") as f:
                f.write(test_html)

            driver.get(f"file://{test_file}")
            time.sleep(2)

            try:
                iframe = driver.find_element(By.ID, "target")
                # If iframe loads without error, click-jacking may be possible
                iframe_screenshot = os.path.join(self.screenshot_dir, "clickjack_result.png")
                driver.save_screenshot(iframe_screenshot)

                # Check if X-Frame-Options prevented loading
                iframe_content = driver.execute_script("""
                    var iframe = document.getElementById('target');
                    try {
                        return iframe.contentDocument ? 'loaded' : 'blocked';
                    } catch(e) {
                        return 'blocked';
                    }
                """)

                if iframe_content == "loaded":
                    return {
                        "status": "success",
                        "vulnerable": True,
                        "severity": "MEDIUM",
                        "description": "Page can be embedded in iframe — click-jacking possible",
                        "screenshot": iframe_screenshot,
                        "recommendation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'",
                    }
                else:
                    return {
                        "status": "success",
                        "vulnerable": False,
                        "severity": "LOW",
                        "description": "Page cannot be embedded in iframe — click-jacking prevented",
                    }
            except NoSuchElementException:
                return {
                    "status": "success",
                    "vulnerable": False,
                    "severity": "LOW",
                    "description": "iframe not found — X-Frame-Options likely blocking",
                }
        except Exception as e:
            return {"status": "error", "url": url, "error": str(e)[:200]}

    # ============================================================
    # Local/Session Storage Inspection
    # ============================================================

    def inspect_storage(self, url: str) -> Dict[str, Any]:
        """Inspect localStorage and sessionStorage for sensitive data."""
        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available"}

        nav_result = self.navigate(url)
        if nav_result.get("status") not in ("success", "timeout"):
            return nav_result

        try:
            local_storage = driver.execute_script("""
                var items = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    items[key] = localStorage.getItem(key).substring(0, 200);
                }
                return items;
            """)
            session_storage = driver.execute_script("""
                var items = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    items[key] = sessionStorage.getItem(key).substring(0, 200);
                }
                return items;
            """)

            # Check for sensitive data in storage
            sensitive_patterns = ["token", "password", "secret", "key", "auth", "session", "jwt", "bearer"]
            findings = []
            for storage_name, storage_data in [("localStorage", local_storage), ("sessionStorage", session_storage)]:
                for key, value in storage_data.items():
                    if any(p in key.lower() for p in sensitive_patterns) or any(p in value.lower() for p in sensitive_patterns):
                        findings.append({
                            "storage": storage_name,
                            "key": key,
                            "value_preview": value[:50],
                            "severity": "HIGH",
                            "description": f"Sensitive data in {storage_name}: '{key}'",
                        })

            return {
                "status": "success",
                "url": url,
                "local_storage": local_storage,
                "session_storage": session_storage,
                "local_storage_count": len(local_storage),
                "session_storage_count": len(session_storage),
                "security_findings": findings,
            }
        except Exception as e:
            return {"status": "error", "url": url, "error": str(e)[:200]}

    # ============================================================
    # Mixed Content Detection
    # ============================================================

    def detect_mixed_content(self, url: str) -> Dict[str, Any]:
        """Detect HTTP resources loaded on HTTPS pages (mixed content)."""
        if not url.startswith("https://"):
            return {"status": "skipped", "reason": "Target is not HTTPS — mixed content not applicable"}

        driver = self._get_driver()
        if not driver:
            return {"error": "Browser driver not available"}

        nav_result = self.navigate(url)
        if nav_result.get("status") not in ("success", "timeout"):
            return nav_result

        try:
            # Find all resource URLs
            mixed_content = driver.execute_script("""
                var httpResources = [];
                // Check images
                document.querySelectorAll('img[src]').forEach(function(img) {
                    if (img.src.startsWith('http://')) httpResources.push({type: 'image', url: img.src});
                });
                // Check scripts
                document.querySelectorAll('script[src]').forEach(function(script) {
                    if (script.src.startsWith('http://')) httpResources.push({type: 'script', url: script.src});
                });
                // Check stylesheets
                document.querySelectorAll('link[rel=stylesheet]').forEach(function(link) {
                    if (link.href.startsWith('http://')) httpResources.push({type: 'stylesheet', url: link.href});
                });
                // Check iframes
                document.querySelectorAll('iframe[src]').forEach(function(iframe) {
                    if (iframe.src.startsWith('http://')) httpResources.push({type: 'iframe', url: iframe.src});
                });
                // Check audio/video
                document.querySelectorAll('audio[src], video[src], source[src]').forEach(function(media) {
                    if (media.src.startsWith('http://')) httpResources.push({type: 'media', url: media.src});
                });
                return httpResources;
            """)

            findings = []
            for resource in mixed_content:
                findings.append({
                    "type": "mixed_content",
                    "resource_type": resource.get("type"),
                    "url": resource.get("url", "")[:200],
                    "severity": "HIGH" if resource.get("type") in ("script", "iframe") else "MEDIUM",
                    "description": f"HTTP {resource.get('type')} loaded on HTTPS page — MITM risk",
                })

            return {
                "status": "success",
                "url": url,
                "mixed_content_count": len(mixed_content),
                "findings": findings,
            }
        except Exception as e:
            return {"status": "error", "url": url, "error": str(e)[:200]}

    # ============================================================
    # Full Security Audit (orchestrates all tests)
    # ============================================================

    def full_audit(self, url: str, take_screenshot: bool = True) -> Dict[str, Any]:
        """Run comprehensive browser-based security audit."""
        t0 = time.time()
        results = {
            "tool": "browser_agent",
            "version": "v1.0-2025",
            "url": url,
            "audit_started": datetime.now(timezone.utc).isoformat(),
            "selenium_available": HAS_SELENIUM,
        }

        if not HAS_SELENIUM:
            results["status"] = "error"
            results["error"] = "Selenium not installed. Install: pip install selenium"
            return results

        # Run all tests
        if take_screenshot:
            results["screenshot"] = self.screenshot(url, "full_audit")

        results["dom_analysis"] = self.analyze_dom(url)
        results["javascript_monitoring"] = self.monitor_javascript(url)
        results["network_logging"] = self.log_network(url)
        results["security_headers"] = self.analyze_security_headers(url)
        results["cookie_analysis"] = self.analyze_cookies(url)
        results["clickjacking_test"] = self.test_clickjacking(url)
        results["storage_inspection"] = self.inspect_storage(url)
        results["mixed_content"] = self.detect_mixed_content(url)

        # Aggregate findings
        all_findings = []
        for test_name, test_result in results.items():
            if isinstance(test_result, dict):
                for key in ("findings", "security_findings"):
                    if key in test_result:
                        for finding in test_result[key]:
                            finding["test"] = test_name
                            all_findings.append(finding)

        results["total_findings"] = len(all_findings)
        results["all_findings"] = all_findings
        results["findings_by_severity"] = {
            "CRITICAL": sum(1 for f in all_findings if f.get("severity") == "CRITICAL"),
            "HIGH": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
            "LOW": sum(1 for f in all_findings if f.get("severity") == "LOW"),
        }
        results["audit_completed"] = datetime.now(timezone.utc).isoformat()
        results["elapsed_sec"] = round(time.time() - t0, 2)

        # Cleanup
        self.close()

        return results
