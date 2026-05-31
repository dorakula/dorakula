#!/usr/bin/env python3
"""DORAKULA API Fuzzer - REST/GraphQL API Security Testing

Comprehensive API fuzzing module covering REST endpoints, GraphQL
introspection, OpenAPI spec parsing, BOLA/IDOR testing, BFLA testing,
and mass assignment detection. Uses aiohttp for async HTTP requests.
"""

import asyncio
import json
import logging
import re
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse, urljoin, quote

logger = logging.getLogger(__name__)

# Try to import aiohttp, fall back to subprocess curl if not available
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    logger.warning("aiohttp not available, falling back to subprocess curl")


class APIFuzzer:
    """Advanced API security fuzzer with REST, GraphQL, and OWASP API testing.

    Fuzzes REST and GraphQL APIs for vulnerabilities including broken
    object-level authorization (BOLA), broken function-level authorization
    (BFLA), mass assignment, and excessive data exposure. Supports OpenAPI
    spec parsing for comprehensive endpoint coverage.

    Attributes:
        ai_router: AI router instance for intelligent fuzzing.
        timeout: Default timeout for HTTP requests in seconds.
        rate_limit: Delay between requests in seconds.
    """

    # Common API endpoint patterns
    REST_ENDPOINTS: List[str] = [
        "/api/v1/users", "/api/v1/user", "/api/v1/admin",
        "/api/v1/products", "/api/v1/orders", "/api/v1/posts",
        "/api/v1/comments", "/api/v1/files", "/api/v1/tokens",
        "/api/v1/config", "/api/v1/settings", "/api/v1/roles",
        "/api/v1/permissions", "/api/v1/groups", "/api/v1/teams",
        "/api/v1/organizations", "/api/v1/secrets", "/api/v1/keys",
        "/api/v1/payments", "/api/v1/invoices", "/api/v1/accounts",
        "/api/v2/users", "/api/v2/admin", "/api/v2/config",
        "/api/users", "/api/admin", "/api/config",
        "/users", "/admin", "/health", "/status", "/metrics",
        "/swagger", "/swagger.json", "/api-docs", "/openapi.json",
        "/graphql", "/graphiql", "/playground",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/debug", "/trace", "/env", "/info",
    ]

    # HTTP methods to test
    HTTP_METHODS: List[str] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    # GraphQL introspection query
    GRAPHQL_INTROSPECTION: str = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    fragment InputValue on __InputValue {
      name
      description
      type {
        ...TypeRef
      }
      defaultValue
    }
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
    """

    def __init__(
        self,
        ai_router: Any = None,
        timeout: int = 30,
        rate_limit: float = 0.1,
    ):
        """Initialize APIFuzzer.

        Args:
            ai_router: AIRouter instance for AI-enhanced operations.
            timeout: Default request timeout in seconds.
            rate_limit: Delay between requests in seconds for rate limiting.
        """
        self.ai_router = ai_router
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._session: Optional[Any] = None
        logger.info("APIFuzzer initialized with timeout=%d, rate_limit=%.2f",
                     timeout, rate_limit)

    async def _get_session(self) -> Any:
        """Get or create aiohttp ClientSession.

        Returns:
            aiohttp.ClientSession instance.
        """
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def _request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict] = None,
        data: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Make an HTTP request using aiohttp or curl fallback.

        Args:
            method: HTTP method.
            url: Target URL.
            headers: Optional request headers.
            json_data: Optional JSON body.
            data: Optional raw body data.

        Returns:
            Dictionary with status, headers, body, and error info.
        """
        result: Dict[str, Any] = {
            "status": 0,
            "headers": {},
            "body": "",
            "error": None,
        }

        if HAS_AIOHTTP:
            try:
                session = await self._get_session()
                async with session.request(
                    method, url,
                    headers=headers or {},
                    json=json_data,
                    data=data,
                ) as response:
                    result["status"] = response.status
                    result["headers"] = dict(response.headers)
                    result["body"] = await response.text()
            except asyncio.TimeoutError:
                result["error"] = "timeout"
            except aiohttp.ClientError as exc:
                result["error"] = str(exc)
            except OSError as exc:
                result["error"] = str(exc)
        else:
            # Fallback to subprocess curl
            try:
                cmd = ["curl", "-s", "-w", "\\n%{http_code}", "-X", method,
                       "--max-time", str(self.timeout)]
                if headers:
                    for key, value in headers.items():
                        cmd.extend(["-H", f"{key}: {value}"])
                if json_data:
                    cmd.extend(["-H", "Content-Type: application/json",
                                "-d", json.dumps(json_data)])
                elif data:
                    cmd.extend(["-d", data])
                cmd.append(url)

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout + 5
                )
                output = stdout.decode("utf-8", errors="replace")
                lines = output.rsplit("\n", 1)
                if len(lines) == 2:
                    result["body"] = lines[0]
                    try:
                        result["status"] = int(lines[1].strip())
                    except ValueError:
                        result["status"] = 0
                else:
                    result["body"] = output
            except asyncio.TimeoutError:
                result["error"] = "timeout"
            except OSError as exc:
                result["error"] = str(exc)

        return result

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def fuzz_rest(self, target: str, endpoints_file: str) -> Dict[str, Any]:
        """Fuzz REST API endpoints for vulnerabilities.

        Tests discovered or provided API endpoints with various HTTP methods,
        authentication bypass techniques, and fuzz payloads.

        Args:
            target: Base target URL.
            endpoints_file: Path to file listing API endpoints (one per line).

        Returns:
            Dictionary containing:
                - discovered_endpoints: Accessible endpoints found
                - findings: Security findings per endpoint
                - authentication_issues: Auth bypass findings
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "discovered_endpoints": [],
            "findings": [],
            "authentication_issues": [],
            "errors": [],
        }

        # Load endpoints from file
        endpoints: List[str] = []
        try:
            with open(endpoints_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    endpoint = line.strip()
                    if endpoint and not endpoint.startswith("#"):
                        endpoints.append(endpoint)
        except FileNotFoundError:
            results["errors"].append(f"Endpoints file not found: {endpoints_file}")
            endpoints = self.REST_ENDPOINTS
        except PermissionError:
            results["errors"].append(f"Permission denied: {endpoints_file}")
            endpoints = self.REST_ENDPOINTS
        except OSError as exc:
            results["errors"].append(f"Error reading endpoints: {exc}")
            endpoints = self.REST_ENDPOINTS

        # Also add built-in endpoints
        all_endpoints: Set[str] = set(endpoints + self.REST_ENDPOINTS)

        semaphore = asyncio.Semaphore(5)

        async def _test_endpoint(endpoint: str) -> None:
            """Test a single API endpoint."""
            async with semaphore:
                url = urljoin(target + "/", endpoint.lstrip("/"))
                for method in self.HTTP_METHODS:
                    try:
                        await asyncio.sleep(self.rate_limit)

                        # Test without authentication
                        resp = await self._request(method, url)
                        status = resp["status"]
                        body = resp["body"]

                        if status == 0:
                            continue

                        endpoint_info: Dict[str, Any] = {
                            "endpoint": endpoint,
                            "method": method,
                            "status": status,
                            "response_length": len(body),
                        }

                        if status in (200, 201, 202, 204):
                            results["discovered_endpoints"].append(endpoint_info)

                            # Check for sensitive data exposure
                            sensitive_patterns = [
                                (r'"password"', "password_field"),
                                (r'"secret"', "secret_field"),
                                (r'"api_key"', "api_key_field"),
                                (r'"token"', "token_field"),
                                (r'"private_key"', "private_key_field"),
                                (r'"credit_card"', "credit_card_field"),
                                (r'"ssn"', "ssn_field"),
                            ]
                            for pattern, field_type in sensitive_patterns:
                                if re.search(pattern, body, re.IGNORECASE):
                                    results["findings"].append({
                                        "type": "sensitive_data_exposure",
                                        "endpoint": endpoint,
                                        "method": method,
                                        "field": field_type,
                                        "severity": "high",
                                    })

                            # Check for excessive data in response
                            try:
                                data = json.loads(body)
                                if isinstance(data, dict):
                                    data_keys = list(data.keys())
                                    if len(data_keys) > 20:
                                        results["findings"].append({
                                            "type": "excessive_data_exposure",
                                            "endpoint": endpoint,
                                            "method": method,
                                            "fields_count": len(data_keys),
                                            "severity": "medium",
                                        })
                            except json.JSONDecodeError:
                                pass

                        elif status == 401:
                            # Test auth bypass
                            bypass_headers: List[Dict[str, str]] = [
                                {"Authorization": "Bearer null"},
                                {"Authorization": "Bearer undefined"},
                                {"Authorization": "Bearer "},
                                {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
                                {"X-Forwarded-For": "127.0.0.1"},
                                {"X-Original-URL": endpoint},
                                {"X-Rewrite-URL": endpoint},
                                {"Content-Type": "application/json"},
                            ]

                            for bypass_header in bypass_headers:
                                bypass_resp = await self._request(method, url, headers=bypass_header)
                                if bypass_resp["status"] in (200, 201, 202, 204):
                                    results["authentication_issues"].append({
                                        "endpoint": endpoint,
                                        "method": method,
                                        "bypass_header": list(bypass_header.keys())[0],
                                        "original_status": status,
                                        "bypassed_status": bypass_resp["status"],
                                        "severity": "critical",
                                    })
                                    break

                        elif status == 403:
                            # Test method-based access control bypass
                            for alt_method in ["PUT", "PATCH", "POST", "DELETE"]:
                                if alt_method != method:
                                    alt_resp = await self._request(alt_method, url)
                                    if alt_resp["status"] in (200, 201, 202, 204):
                                        results["authentication_issues"].append({
                                            "endpoint": endpoint,
                                            "method": alt_method,
                                            "original_method": method,
                                            "original_status": status,
                                            "bypassed_status": alt_resp["status"],
                                            "bypass_type": "method_override",
                                            "severity": "high",
                                        })

                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        results["errors"].append(
                            f"Error testing {method} {endpoint}: {exc}"
                        )

        tasks = [_test_endpoint(ep) for ep in all_endpoints]
        await asyncio.gather(*tasks, return_exceptions=True)

        # AI analysis
        if self.ai_router and results["findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"API fuzzing results for {target}. Analyze:\n"
                    f"Discovered endpoints: {len(results['discovered_endpoints'])}\n"
                    f"Security findings: {json.dumps(results['findings'][:5], indent=2)}\n"
                    f"Auth issues: {json.dumps(results['authentication_issues'][:5], indent=2)}",
                    context="api_fuzz_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI API fuzz analysis failed: %s", exc)

        logger.info("REST API fuzzing complete: %d endpoints, %d findings",
                     len(results["discovered_endpoints"]), len(results["findings"]))
        return results

    async def fuzz_graphql(self, target: str) -> Dict[str, Any]:
        """Fuzz GraphQL API via introspection and abuse techniques.

        Performs GraphQL introspection to discover schema, then tests
        for authorization bypass, query depth attacks, and mutation abuse.

        Args:
            target: GraphQL endpoint URL.

        Returns:
            Dictionary containing:
                - schema: Discovered GraphQL schema
                - queries: Available query types
                - mutations: Available mutation types
                - findings: Security findings
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "schema": {},
            "queries": [],
            "mutations": [],
            "findings": [],
            "errors": [],
        }

        # Step 1: Introspection query
        try:
            resp = await self._request(
                "POST", target,
                headers={"Content-Type": "application/json"},
                json_data={"query": self.GRAPHQL_INTROSPECTION},
            )

            if resp["status"] == 200:
                try:
                    introspection_data = json.loads(resp["body"])
                    schema = introspection_data.get("data", {}).get("__schema", {})
                    results["schema"] = schema

                    # Extract queries and mutations
                    query_type = schema.get("queryType", {})
                    mutation_type = schema.get("mutationType", {})
                    types = schema.get("types", [])

                    results["queries"].append({
                        "name": query_type.get("name", "Query"),
                    })
                    results["mutations"].append({
                        "name": mutation_type.get("name", "Mutation"),
                    })

                    # Extract detailed type information
                    for t in types:
                        type_name = t.get("name", "")
                        if type_name.startswith("__"):
                            continue
                        fields = t.get("fields", [])
                        if fields:
                            for field in fields:
                                field_name = field.get("name", "")
                                args = field.get("args", [])
                                if query_type.get("name") and type_name == query_type.get("name"):
                                    results["queries"].append({
                                        "field": field_name,
                                        "args": [{"name": a.get("name"), "type": str(a.get("type", {}))}
                                                 for a in args],
                                    })
                                elif mutation_type.get("name") and type_name == mutation_type.get("name"):
                                    results["mutations"].append({
                                        "field": field_name,
                                        "args": [{"name": a.get("name"), "type": str(a.get("type", {}))}
                                                 for a in args],
                                    })

                    results["findings"].append({
                        "type": "introspection_enabled",
                        "severity": "medium",
                        "description": "GraphQL introspection is enabled - full schema exposed",
                    })

                except json.JSONDecodeError:
                    results["errors"].append("Introspection response is not valid JSON")
            else:
                # Introspection might be disabled
                results["findings"].append({
                    "type": "introspection_disabled",
                    "severity": "info",
                    "description": f"Introspection returned status {resp['status']}",
                })

        except asyncio.TimeoutError:
            results["errors"].append("GraphQL introspection timed out")
        except OSError as exc:
            results["errors"].append(f"GraphQL request error: {exc}")

        # Step 2: Test common GraphQL queries
        common_queries: List[Dict[str, str]] = [
            {
                "name": "users_query",
                "query": "{ users { id email username role password } }",
                "description": "Attempt to query user data including sensitive fields",
            },
            {
                "name": "all_users",
                "query": "{ allUsers { id email } }",
                "description": "Query all users",
            },
            {
                "name": "me_query",
                "query": "{ me { id email role permissions } }",
                "description": "Query current user info",
            },
            {
                "name": "admin_query",
                "query": "{ admin { id email role secret } }",
                "description": "Attempt admin query",
            },
        ]

        for q in common_queries:
            try:
                resp = await self._request(
                    "POST", target,
                    headers={"Content-Type": "application/json"},
                    json_data={"query": q["query"]},
                )

                if resp["status"] == 200:
                    body = resp["body"]
                    try:
                        data = json.loads(body)
                        if "errors" not in data or not data.get("errors"):
                            results["findings"].append({
                                "type": "unauthorized_query_access",
                                "query": q["name"],
                                "description": q["description"],
                                "severity": "high",
                                "response_keys": list(data.get("data", {}).keys()) if isinstance(data.get("data"), dict) else [],
                            })
                        # Check for sensitive data in response
                        body_lower = body.lower()
                        if any(s in body_lower for s in ["password", "secret", "token", "api_key"]):
                            results["findings"].append({
                                "type": "sensitive_data_in_graphql",
                                "query": q["name"],
                                "severity": "critical",
                                "description": "Sensitive data exposed via GraphQL query",
                            })
                    except json.JSONDecodeError:
                        pass
            except (asyncio.TimeoutError, OSError):
                pass

        # Step 3: Test query depth attack (DoS)
        depth_payloads: List[str] = [
            # Deep nesting
            "{" + "user{" + "friends{" * 5 + "id" + "}" * 6 + "}",
            # Batch query attack
            '{"query":"{ user { id } }","operationName":"q1"},'
            '{"query":"{ user { id } }","operationName":"q2"},'
            '{"query":"{ user { id } }","operationName":"q3"}',
        ]

        for depth_query in depth_payloads:
            try:
                start_time = asyncio.get_event_loop().time()
                resp = await self._request(
                    "POST", target,
                    headers={"Content-Type": "application/json"},
                    json_data={"query": depth_query},
                )
                elapsed = asyncio.get_event_loop().time() - start_time

                if elapsed > 5:
                    results["findings"].append({
                        "type": "query_depth_dos",
                        "severity": "high",
                        "response_time": round(elapsed, 3),
                        "description": "Deep query caused significant server delay - DoS risk",
                    })
            except (asyncio.TimeoutError, OSError):
                pass

        # Step 4: Test error-based information disclosure
        error_payloads: List[str] = [
            '{ __typename }',
            '{ nonExistentField }',
            '{ user(id: 1) { nonExistent } }',
        ]

        for err_query in error_payloads:
            try:
                resp = await self._request(
                    "POST", target,
                    headers={"Content-Type": "application/json"},
                    json_data={"query": err_query},
                )
                if resp["status"] == 200:
                    body = resp["body"]
                    error_indicators = ["stack", "trace", "debug", "internal", "exception"]
                    for indicator in error_indicators:
                        if indicator in body.lower():
                            results["findings"].append({
                                "type": "error_information_disclosure",
                                "severity": "medium",
                                "indicator": indicator,
                                "description": f"Error response contains {indicator} information",
                            })
                            break
            except (asyncio.TimeoutError, OSError):
                pass

        # AI analysis
        if self.ai_router and results["findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"GraphQL fuzzing results for {target}:\n"
                    f"Queries discovered: {len(results['queries'])}\n"
                    f"Mutations discovered: {len(results['mutations'])}\n"
                    f"Findings: {json.dumps(results['findings'][:5], indent=2)}\n"
                    f"Suggest exploitation strategies for these findings.",
                    context="graphql_fuzz_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI GraphQL analysis failed: %s", exc)

        logger.info("GraphQL fuzzing complete: %d queries, %d mutations, %d findings",
                     len(results["queries"]), len(results["mutations"]),
                     len(results["findings"]))
        return results

    async def fuzz_openapi(self, spec_url: str) -> Dict[str, Any]:
        """Parse OpenAPI specification and fuzz all endpoints.

        Downloads and parses an OpenAPI/Swagger specification, then
        systematically tests each endpoint with various payloads and
        authentication states.

        Args:
            spec_url: URL to the OpenAPI specification JSON/YAML.

        Returns:
            Dictionary containing:
                - spec_info: Parsed specification metadata
                - endpoints: Discovered endpoints from spec
                - findings: Security findings per endpoint
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "spec_url": spec_url,
            "spec_info": {},
            "endpoints": [],
            "findings": [],
            "errors": [],
        }

        # Fetch the spec
        try:
            resp = await self._request("GET", spec_url)
            if resp["status"] != 200:
                results["errors"].append(f"Failed to fetch spec: status {resp['status']}")
                return results

            spec_body = resp["body"]

            # Try to parse as JSON
            try:
                spec = json.loads(spec_body)
            except json.JSONDecodeError:
                # Try YAML parsing (basic)
                results["errors"].append("Spec is not valid JSON - YAML parsing not supported in this version")
                return results

        except (asyncio.TimeoutError, OSError) as exc:
            results["errors"].append(f"Error fetching spec: {exc}")
            return results

        # Parse spec metadata
        results["spec_info"] = {
            "title": spec.get("info", {}).get("title", "Unknown"),
            "version": spec.get("info", {}).get("version", "Unknown"),
            "openapi": spec.get("openapi", spec.get("swagger", "Unknown")),
        }

        # Extract base URL
        base_url: str = ""
        servers = spec.get("servers", [])
        if servers:
            base_url = servers[0].get("url", "")
        if not base_url:
            host = spec.get("host", "")
            schemes = spec.get("schemes", ["https"])
            base_path = spec.get("basePath", "")
            if host:
                base_url = f"{schemes[0]}://{host}{base_path}"

        if not base_url:
            parsed = urlparse(spec_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Extract endpoints and test
        paths = spec.get("paths", {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                    continue

                endpoint: Dict[str, Any] = {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": operation.get("operationId", ""),
                    "summary": operation.get("summary", ""),
                    "parameters": operation.get("parameters", []),
                    "security": operation.get("security", spec.get("security", [])),
                }
                results["endpoints"].append(endpoint)

                # Build and test the endpoint URL
                test_url = base_url.rstrip("/") + path

                # Replace path parameters with test values
                test_url = re.sub(r"\{(\w+)\}", "1", test_url)

                # Test the endpoint
                try:
                    await asyncio.sleep(self.rate_limit)

                    # Test without auth
                    resp = await self._request(method.upper(), test_url)
                    status = resp["status"]

                    # Build query parameters
                    query_params: Dict[str, str] = {}
                    request_body: Optional[Dict] = None

                    for param in operation.get("parameters", []):
                        param_name = param.get("name", "")
                        param_in = param.get("in", "")
                        param_type = param.get("schema", {}).get("type", "string")

                        test_value = self._generate_test_value(param_type, param_name)

                        if param_in == "query":
                            query_params[param_name] = test_value
                        elif param_in == "header":
                            pass  # Headers handled separately
                        elif param_in == "path":
                            pass  # Already replaced above

                    # Build request body
                    request_body_schema = operation.get("requestBody", {})
                    if request_body_schema:
                        content = request_body_schema.get("content", {})
                        json_schema = content.get("application/json", {}).get("schema", {})
                        if json_schema:
                            request_body = self._generate_test_object(json_schema, spec)

                    # Make request with parameters
                    if query_params:
                        param_str = "&".join(f"{k}={quote(v)}" for k, v in query_params.items())
                        test_url_with_params = f"{test_url}?{param_str}"
                    else:
                        test_url_with_params = test_url

                    resp = await self._request(
                        method.upper(), test_url_with_params,
                        json_data=request_body,
                    )

                    if resp["status"] in (200, 201, 202, 204):
                        # Check for security issues
                        body = resp["body"]
                        body_lower = body.lower()

                        # Sensitive data exposure
                        sensitive_fields = ["password", "secret", "token", "api_key",
                                           "credit_card", "ssn", "private_key"]
                        for field in sensitive_fields:
                            if field in body_lower:
                                results["findings"].append({
                                    "type": "sensitive_data_exposure",
                                    "endpoint": path,
                                    "method": method.upper(),
                                    "field": field,
                                    "severity": "high",
                                })

                        # Missing rate limiting (check response headers)
                        headers = resp.get("headers", {})
                        rate_limit_headers = ["x-ratelimit-limit", "ratelimit-limit",
                                              "x-ratelimit-remaining"]
                        has_rate_limit = any(h.lower() in [k.lower() for k in headers]
                                             for h in rate_limit_headers)
                        if not has_rate_limit:
                            results["findings"].append({
                                "type": "missing_rate_limiting",
                                "endpoint": path,
                                "method": method.upper(),
                                "severity": "low",
                            })

                    elif resp["status"] == 401:
                        # Endpoint requires auth - test auth bypass
                        auth_bypass_headers = [
                            {"Authorization": "Bearer null"},
                            {"Authorization": "Basic YWRtaW46YWRtaW4="},
                        ]
                        for bypass in auth_bypass_headers:
                            bypass_resp = await self._request(
                                method.upper(), test_url_with_params,
                                headers=bypass,
                                json_data=request_body,
                            )
                            if bypass_resp["status"] in (200, 201, 202, 204):
                                results["findings"].append({
                                    "type": "auth_bypass",
                                    "endpoint": path,
                                    "method": method.upper(),
                                    "bypass_header": list(bypass.keys())[0],
                                    "severity": "critical",
                                })
                                break

                except asyncio.TimeoutError:
                    results["errors"].append(f"Timeout testing {method.upper()} {path}")
                except OSError as exc:
                    results["errors"].append(f"Error testing {method.upper()} {path}: {exc}")

        # AI analysis
        if self.ai_router and results["findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"OpenAPI spec analysis for {spec_url}:\n"
                    f"Endpoints: {len(results['endpoints'])}\n"
                    f"Findings: {json.dumps(results['findings'][:5], indent=2)}\n"
                    f"Suggest prioritized testing strategy.",
                    context="openapi_fuzz_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI OpenAPI analysis failed: %s", exc)

        logger.info("OpenAPI fuzzing complete: %d endpoints, %d findings",
                     len(results["endpoints"]), len(results["findings"]))
        return results

    @staticmethod
    def _generate_test_value(param_type: str, param_name: str) -> str:
        """Generate a test value for a parameter based on its type and name.

        Args:
            param_type: Parameter type (string, integer, boolean, etc.).
            param_name: Parameter name for context-aware value generation.

        Returns:
            String test value.
        """
        name_lower = param_name.lower()

        if "id" in name_lower:
            return "1"
        elif "email" in name_lower:
            return "test@test.com"
        elif "url" in name_lower or "uri" in name_lower:
            return "https://example.com"
        elif "date" in name_lower:
            return "2024-01-01"
        elif "name" in name_lower:
            return "test"
        elif param_type == "integer":
            return "1"
        elif param_type == "boolean":
            return "true"
        elif param_type == "number":
            return "1.0"
        else:
            return "test_value"

    def _generate_test_object(self, schema: Dict, full_spec: Dict) -> Dict:
        """Generate a test object from a JSON schema.

        Args:
            schema: JSON schema definition.
            full_spec: Full OpenAPI spec for resolving $ref.

        Returns:
            Dictionary with generated test values.
        """
        result: Dict[str, Any] = {}

        # Resolve $ref
        if "$ref" in schema:
            ref_path = schema["$ref"]
            try:
                parts = ref_path.replace("#/", "").split("/")
                resolved = full_spec
                for part in parts:
                    resolved = resolved.get(part, {})
                schema = resolved if resolved else schema
            except (KeyError, IndexError):
                pass

        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get("type", "string")
            result[prop_name] = self._generate_test_value(prop_type, prop_name)

        return result

    async def test_bola(self, target: str, endpoint: str, ids: List[str]) -> Dict[str, Any]:
        """Test Broken Object Level Authorization (BOLA/IDOR).

        Tests whether accessing objects with different IDs is possible
        without proper authorization checks.

        Args:
            target: Base target URL.
            endpoint: API endpoint pattern with {id} placeholder.
            ids: List of object IDs to test access to.

        Returns:
            Dictionary containing:
                - accessible_objects: Objects accessible without authorization
                - idor_findings: IDOR vulnerability findings
                - tested_combinations: Number of ID-method combinations tested
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "endpoint": endpoint,
            "accessible_objects": [],
            "idor_findings": [],
            "tested_combinations": 0,
            "errors": [],
        }

        # Test each ID with different methods
        for obj_id in ids:
            test_url = endpoint.replace("{id}", str(obj_id))
            if not test_url.startswith("http"):
                test_url = urljoin(target + "/", test_url.lstrip("/"))

            for method in ["GET", "PUT", "PATCH", "DELETE"]:
                results["tested_combinations"] += 1
                try:
                    await asyncio.sleep(self.rate_limit)

                    # Test without any auth
                    resp = await self._request(method, test_url)

                    if resp["status"] in (200, 201, 202, 204):
                        results["accessible_objects"].append({
                            "id": obj_id,
                            "method": method,
                            "status": resp["status"],
                            "response_length": len(resp["body"]),
                        })

                        # Check if response contains data (BOLA confirmed)
                        if method == "GET" and len(resp["body"]) > 10:
                            results["idor_findings"].append({
                                "type": "bola_idor",
                                "object_id": obj_id,
                                "method": method,
                                "status": resp["status"],
                                "severity": "critical",
                                "description": f"Object {obj_id} accessible without authorization via {method}",
                                "response_preview": resp["body"][:200],
                            })

                    elif resp["status"] == 401:
                        # Test with different auth tokens
                        auth_tests: List[Dict[str, str]] = [
                            {"Authorization": "Bearer victim_token"},
                            {"Authorization": "Bearer admin_token"},
                            {"Cookie": "session=victim_session"},
                        ]

                        for auth_header in auth_tests:
                            auth_resp = await self._request(method, test_url, headers=auth_header)
                            if auth_resp["status"] in (200, 201, 202, 204) and len(auth_resp["body"]) > 10:
                                results["idor_findings"].append({
                                    "type": "bola_with_auth",
                                    "object_id": obj_id,
                                    "method": method,
                                    "auth_header": list(auth_header.keys())[0],
                                    "severity": "high",
                                    "description": f"Object {obj_id} accessible with different user token",
                                })
                                break

                except asyncio.TimeoutError:
                    results["errors"].append(f"Timeout testing {method} {test_url}")
                except OSError as exc:
                    results["errors"].append(f"Error testing {method} {test_url}: {exc}")

        # Test ID predictability
        if len(ids) >= 2:
            try:
                id_values = [int(i) for i in ids if str(i).isdigit()]
                if id_values:
                    differences = [id_values[i+1] - id_values[i] for i in range(len(id_values)-1)]
                    if all(d == differences[0] for d in differences):
                        results["idor_findings"].append({
                            "type": "predictable_ids",
                            "severity": "medium",
                            "description": f"Object IDs are predictable (incrementing by {differences[0]})",
                        })
            except (ValueError, IndexError):
                pass

        # UUID vs sequential ID analysis
        uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
        sequential_count = sum(1 for i in ids if str(i).isdigit())
        if sequential_count > len(ids) * 0.5:
            results["idor_findings"].append({
                "type": "sequential_ids",
                "severity": "medium",
                "description": "API uses sequential numeric IDs - easy to enumerate",
            })

        # AI analysis
        if self.ai_router and results["idor_findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"BOLA/IDOR test results for {target}:\n"
                    f"Findings: {json.dumps(results['idor_findings'][:5], indent=2)}\n"
                    f"Accessible objects: {len(results['accessible_objects'])}\n"
                    f"Suggest additional IDOR testing strategies and data exfiltration techniques.",
                    context="bola_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI BOLA analysis failed: %s", exc)

        logger.info("BOLA test complete: %d findings, %d accessible objects",
                     len(results["idor_findings"]), len(results["accessible_objects"]))
        return results

    async def test_bfla(self, target: str, endpoint: str) -> Dict[str, Any]:
        """Test Broken Function Level Authorization (BFLA).

        Tests whether lower-privilege users can access admin-only
        functions and endpoints.

        Args:
            target: Base target URL.
            endpoint: Admin endpoint to test for BFLA.

        Returns:
            Dictionary containing:
                - bfla_findings: BFLA vulnerability findings
                - tested_scenarios: Authorization test scenarios
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "endpoint": endpoint,
            "bfla_findings": [],
            "tested_scenarios": [],
            "errors": [],
        }

        test_url = endpoint if endpoint.startswith("http") else urljoin(target + "/", endpoint.lstrip("/"))

        # Test with various privilege levels
        privilege_levels: List[Dict[str, Any]] = [
            {
                "name": "unauthenticated",
                "headers": {},
                "expected_denial": True,
            },
            {
                "name": "regular_user",
                "headers": {"Authorization": "Bearer regular_user_token"},
                "expected_denial": True,
            },
            {
                "name": "low_privilege",
                "headers": {"Authorization": "Bearer low_privilege_token"},
                "expected_denial": True,
            },
        ]

        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            for level in privilege_levels:
                try:
                    await asyncio.sleep(self.rate_limit)

                    resp = await self._request(method, test_url, headers=level["headers"])
                    status = resp["status"]

                    scenario: Dict[str, Any] = {
                        "method": method,
                        "privilege_level": level["name"],
                        "status": status,
                        "response_length": len(resp["body"]),
                        "expected_denied": level["expected_denial"],
                    }
                    results["tested_scenarios"].append(scenario)

                    # If we expected denial but got success
                    if level["expected_denial"] and status in (200, 201, 202, 204):
                        results["bfla_findings"].append({
                            "type": "bfla_violation",
                            "method": method,
                            "privilege_level": level["name"],
                            "status": status,
                            "severity": "critical",
                            "description": (
                                f"Admin function accessible by {level['name']} user "
                                f"via {method} request"
                            ),
                        })

                except asyncio.TimeoutError:
                    results["errors"].append(
                        f"Timeout testing {method} with {level['name']}"
                    )
                except OSError as exc:
                    results["errors"].append(f"Request error: {exc}")

        # Test HTTP method override
        override_headers: List[Dict[str, str]] = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-Method-Override": "DELETE"},
            {"X-HTTP-Method": "DELETE"},
        ]

        for override in override_headers:
            try:
                resp = await self._request("POST", test_url, headers=override)
                if resp["status"] in (200, 201, 202, 204):
                    results["bfla_findings"].append({
                        "type": "method_override_bfla",
                        "override_header": list(override.keys())[0],
                        "status": resp["status"],
                        "severity": "high",
                        "description": "HTTP method override allows bypassing authorization",
                    })
            except (asyncio.TimeoutError, OSError):
                pass

        # Test path-based bypass
        bypass_paths: List[str] = [
            test_url + "/",
            test_url + "/.",
            test_url + "/..;",
            test_url.replace("/api/", "/api/v2/"),
            test_url.replace("/admin/", "/Admin/"),
        ]

        for bypass_url in bypass_paths:
            try:
                resp = await self._request("GET", bypass_url)
                if resp["status"] == 200:
                    results["bfla_findings"].append({
                        "type": "path_bypass_bfla",
                        "bypass_url": bypass_url,
                        "status": resp["status"],
                        "severity": "high",
                        "description": "Path manipulation bypasses authorization",
                    })
            except (asyncio.TimeoutError, OSError):
                pass

        # AI analysis
        if self.ai_router and results["bfla_findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"BFLA test results for {target}:\n"
                    f"Findings: {json.dumps(results['bfla_findings'][:5], indent=2)}\n"
                    f"Suggest additional authorization testing techniques.",
                    context="bfla_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI BFLA analysis failed: %s", exc)

        logger.info("BFLA test complete: %d findings",
                     len(results["bfla_findings"]))
        return results

    async def test_mass_assignment(self, target: str, endpoint: str) -> Dict[str, Any]:
        """Test for Mass Assignment vulnerabilities.

        Attempts to inject additional fields in API requests to modify
        object properties that should not be user-controllable.

        Args:
            target: Base target URL.
            endpoint: API endpoint to test for mass assignment.

        Returns:
            Dictionary containing:
                - mass_assignment_findings: Mass assignment vulnerabilities found
                - tested_fields: Fields tested for mass assignment
                - errors: List of any errors encountered
        """
        results: Dict[str, Any] = {
            "target": target,
            "endpoint": endpoint,
            "mass_assignment_findings": [],
            "tested_fields": [],
            "errors": [],
        }

        test_url = endpoint if endpoint.startswith("http") else urljoin(target + "/", endpoint.lstrip("/"))

        # First, get the baseline response
        baseline_body: str = ""
        try:
            resp = await self._request("GET", test_url)
            if resp["status"] == 200:
                baseline_body = resp["body"]
        except (asyncio.TimeoutError, OSError):
            pass

        # Mass assignment test fields
        sensitive_fields: List[Dict[str, Any]] = [
            {"field": "role", "values": ["admin", "administrator", "root", "superuser"]},
            {"field": "is_admin", "values": [True, 1, "true"]},
            {"field": "isAdmin", "values": [True, 1, "true"]},
            {"field": "is_administrator", "values": [True, 1, "true"]},
            {"field": "permissions", "values": [["admin", "read", "write"], ["*"]]},
            {"field": "user_type", "values": ["admin", "premium", "enterprise"]},
            {"field": "account_type", "values": ["admin", "premium", "enterprise"]},
            {"field": "email_verified", "values": [True, 1]},
            {"field": "verified", "values": [True, 1]},
            {"field": "active", "values": [True, 1]},
            {"field": "enabled", "values": [True, 1]},
            {"field": "plan", "values": ["premium", "enterprise", "unlimited"]},
            {"field": "subscription", "values": ["premium", "enterprise"]},
            {"field": "balance", "values": [999999, 0]},
            {"field": "credit", "values": [999999, 0]},
            {"field": "price", "values": [0, 0.01]},
            {"field": "amount", "values": [0, 0.01]},
            {"field": "discount", "values": [100, 99.99]},
            {"field": "__v", "values": [0]},
            {"field": "_id", "values": ["admin_user_id"]},
            {"field": "id", "values": ["1", "admin"]},
            {"field": "password", "values": ["newpassword123"]},
            {"field": "password_hash", "values": ["$2b$10$invalidhash"]},
        ]

        # Test with POST and PUT
        for method in ["POST", "PUT", "PATCH"]:
            for field_info in sensitive_fields:
                field_name = field_info["field"]
                for value in field_info["values"]:
                    test_payload = {field_name: value}

                    try:
                        await asyncio.sleep(self.rate_limit)

                        resp = await self._request(
                            method, test_url,
                            headers={"Content-Type": "application/json"},
                            json_data=test_payload,
                        )

                        results["tested_fields"].append({
                            "method": method,
                            "field": field_name,
                            "value": str(value),
                            "status": resp["status"],
                        })

                        # Check if the field was accepted
                        if resp["status"] in (200, 201, 202, 204):
                            response_body = resp["body"]

                            # Check if the modified field appears in response
                            if field_name in response_body:
                                try:
                                    response_data = json.loads(response_body)
                                    if isinstance(response_data, dict):
                                        # Check if field was actually set
                                        returned_value = response_data.get(field_name)
                                        if returned_value is not None:
                                            results["mass_assignment_findings"].append({
                                                "type": "mass_assignment",
                                                "method": method,
                                                "field": field_name,
                                                "injected_value": str(value),
                                                "returned_value": str(returned_value),
                                                "severity": "critical",
                                                "description": (
                                                    f"Field '{field_name}' was accepted and persisted "
                                                    f"via {method} request"
                                                ),
                                            })
                                except json.JSONDecodeError:
                                    # Non-JSON response but field name appears
                                    results["mass_assignment_findings"].append({
                                        "type": "potential_mass_assignment",
                                        "method": method,
                                        "field": field_name,
                                        "injected_value": str(value),
                                        "severity": "high",
                                        "description": f"Field '{field_name}' appears in response",
                                    })

                        elif resp["status"] == 400:
                            # Bad request might indicate field validation
                            pass  # Good - server rejects unknown fields

                    except asyncio.TimeoutError:
                        results["errors"].append(
                            f"Timeout testing {method} with {field_name}={value}"
                        )
                    except OSError as exc:
                        results["errors"].append(f"Request error: {exc}")

        # AI analysis
        if self.ai_router and results["mass_assignment_findings"]:
            try:
                ai_result = await self.ai_router.query(
                    f"Mass assignment test results for {target}:\n"
                    f"Findings: {json.dumps(results['mass_assignment_findings'][:5], indent=2)}\n"
                    f"Suggest additional fields to test based on the API context.",
                    context="mass_assignment_analysis"
                )
                results["ai_analysis"] = ai_result
            except (AttributeError, OSError, RuntimeError) as exc:
                logger.warning("AI mass assignment analysis failed: %s", exc)

        logger.info("Mass assignment test complete: %d findings",
                     len(results["mass_assignment_findings"]))
        return results
