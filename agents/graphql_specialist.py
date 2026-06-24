#!/usr/bin/env python3
"""DORAKULA Modern API & GraphQL Specialist.

GraphQL introspection, depth limit, batch query attacks, gRPC fuzzing.
"""
import logging, json
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class GraphQLSpecialist:
    """GraphQL and gRPC security scanner."""

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
            type { name kind }
          }
        }
      }
    }
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

    BATCH_ATTACK_QUERY = [
        {"query": "{ user { id } }"},
        {"query": "{ user { id } }"},
        {"query": "{ user { id } }"},
        {"query": "{ user { id } }"},
        {"query": "{ user { id } }"},
    ]

    def __init__(self):
        pass

    def introspect(self, target: str) -> Dict:
        """Run GraphQL introspection query."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        try:
            resp = requests.post(target, json={"query": self.INTROSPECTION_QUERY}, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                return {
                    "introspection": "enabled",
                    "types_count": len(types),
                    "severity": "MEDIUM" if types else "LOW",
                    "sample_types": [t.get("name") for t in types[:10] if t.get("name")],
                    "raw_snippet": json.dumps(data)[:500],
                }
            return {"introspection": "disabled_or_blocked", "status": resp.status_code}
        except Exception as e:
            return {"error": str(e)}

    def test_depth_limit(self, target: str) -> Dict:
        """Test for query depth limit vulnerability."""
        if not HAS_REQUESTS:
            return {"error": "requests not available"}
        try:
            resp = requests.post(target, json={"query": self.DEPTH_ATTACK_QUERY}, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if "errors" in data and any("depth" in str(e).lower() for e in data["errors"]):
                    return {"depth_limit": "enforced", "severity": "LOW"}
                return {"depth_limit": "not_enforced", "severity": "HIGH", "response_snippet": json.dumps(data)[:300]}
            return {"status": resp.status_code, "note": "Non-200 response"}
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

    def full_scan(self, target: str) -> Dict:
        """Run all GraphQL tests."""
        return {
            "target": target,
            "introspection": self.introspect(target),
            "depth_limit": self.test_depth_limit(target),
            "batch_attack": self.test_batch_attack(target),
            "field_suggestion": self.test_field_suggestion(target),
        }
