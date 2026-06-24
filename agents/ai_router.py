#!/usr/bin/env python3
"""Dorakula AI Router - OLLAMA SOLE PROVIDER
Clean, single-provider architecture. No failover dead-weight.
Ollama runs locally, always available, zero external dependency.
"""
import os
import json
import time
import logging
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
from collections import OrderedDict

logger = logging.getLogger(__name__)
os.environ["OLLAMA_KEEP_ALIVE"] = "0"


class LRUCache:
    """Thread-safe LRU cache for AI responses."""

    def __init__(self, max_size: int = 500, ttl: int = 3600):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if time.time() - entry["ts"] < self.ttl:
                    self.hits += 1
                    self._cache.move_to_end(key)
                    return entry["value"]
                del self._cache[key]
            self.misses += 1
            return None

    def set(self, key: str, value: Any):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = {"value": value, "ts": time.time()}
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

    def clear(self):
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "entries": len(self._cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / max(1, self.hits + self.misses), 3),
                "ttl": self.ttl,
            }


class AIRouter:
    """Ollama-only AI Router. Clean, fast, sovereign.

    No Puter.js. No Mistral. No Grok. No z.ai.
    Just Ollama. Local. Free. Forever.
    """

    def __init__(self, config):
        self.config = config
        self.ollama_url = getattr(config, "ollama_url", "http://localhost:11434")
        self.ollama_model = getattr(config, "ollama_model", "tinyllama:latest")
        self.cache = LRUCache(
            max_size=getattr(config, "cache_max_size", 500),
            ttl=getattr(config, "cache_ttl", 3600),
        )
        self._stats = {
            "total_calls": 0,
            "ollama_calls": 0,
            "ollama_failures": 0,
            "cache_hits": 0,
            "avg_response_time": 0.0,
            "_total_time": 0.0,
        }
        self._available = False
        self._check_ollama()
        logger.info(
            "AIRouter: OLLAMA-ONLY mode | url=%s | model=%s | available=%s",
            self.ollama_url, self.ollama_model, self._available,
        )

    def _check_ollama(self):
        """Verify Ollama is reachable."""
        try:
            import requests as req
            resp = req.get(f"{self.ollama_url}/api/tags", timeout=5)
            self._available = resp.status_code == 200
            if self._available:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                logger.info("Ollama models available: %s", models)
                if self.ollama_model not in models:
                    # Try exact match or prefix match
                    matched = [m for m in models if m.startswith(self.ollama_model.split(":")[0])]
                    if matched:
                        self.ollama_model = matched[0]
                        logger.info("Auto-selected Ollama model: %s", self.ollama_model)
        except Exception as e:
            logger.warning("Ollama not reachable: %s", e)
            self._available = False


    def _unload_model(self):
        """Unload model from Ollama RAM after inference."""
        try:
            import requests as req
            req.delete(f"{self.ollama_url}/api/generate", json={"model": self.ollama_model, "keep_alive": 0}, timeout=5)
        except Exception as e:
            logger.debug("Failed to unload Ollama model: %s", e)

    def smart_call(self, prompt, context=None, fallback_result=None, timeout=30):
        """Smart call: short timeout, fallback, model unload.
        DEPRECATED: Use query() or analyze() instead.
        """
        import hashlib
        self._stats["total_calls"] += 1
        ck = hashlib.sha256(f"{prompt}|{context}".encode()).hexdigest()
        cached = self.cache.get(ck)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return {**cached, "cached": True}
        if not self._available:
            if fallback_result is not None:
                self._stats["fallback_calls"] += 1
                return {**fallback_result, "fallback": True, "provider": "rule-based"}
            return {"success": False, "error": "Ollama not available", "provider": "ollama"}
        try:
            result = self._call_ollama(prompt, context)
            if result.get("success"):
                self.cache.set(ck, result)
            return result
        finally:
            self._unload_model()

    def query(self, prompt: str, context: Optional[Dict] = None, prefer: str = "") -> Dict[str, Any]:
        """Query method for AI features. Alias for analyze()."""
        return self.analyze(prompt, context, prefer)

    async def query_async(self, prompt: str, context: Optional[Dict] = None, prefer: str = "") -> Dict[str, Any]:
        """Async query method for AI features."""
        return await self.analyze_async(prompt, context, prefer)

    async def analyze_async(self, prompt: str, context: Optional[Dict] = None, prefer: str = "") -> Dict[str, Any]:
        """Async analyze - calls Ollama via aiohttp."""
        self._stats["total_calls"] += 1

        # Check cache
        cache_key = hashlib_sha256(f"{prompt}|{json.dumps(context or {}, sort_keys=True)}")
        cached = self.cache.get(cache_key)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return {**cached, "cached": True}

        if not self._available:
            return {"success": False, "error": "Ollama not available - ensure 'ollama serve' is running", "provider": "ollama"}

        result = await self._call_ollama_async(prompt, context)
        if result.get("success"):
            self.cache.set(cache_key, result)
        return result

    async def chat_async(self, messages: List[Dict[str, str]], temperature: float = 0.3,
                         max_tokens: int = 4096) -> Dict[str, Any]:
        """Async chat completion via Ollama using aiohttp."""
        self._stats["total_calls"] += 1
        if not self._available:
            return {"success": False, "error": "Ollama not available", "provider": "ollama"}

        try:
            import aiohttp
            start = time.time()
            payload = {
                "model": self.ollama_model,
                "messages": messages,
                "stream": False,
                "keep_alive": 0,
                "options": {"temperature": temperature, "num_predict": max_tokens},
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.ollama_url}/api/chat", json=payload, timeout=180) as resp:
                    data = await resp.json()
            elapsed = time.time() - start

            content = data.get("message", {}).get("content", "")
            self._stats["ollama_calls"] += 1
            self._stats["_total_time"] += elapsed
            self._stats["avg_response_time"] = round(
                self._stats["_total_time"] / max(1, self._stats["ollama_calls"]), 3
            )
            return {
                "success": True,
                "result": content,
                "content": content,
                "provider": "ollama",
                "model": self.ollama_model,
                "duration": round(elapsed, 3),
            }
        except Exception as e:
            self._stats["ollama_failures"] += 1
            return {"success": False, "error": str(e), "provider": "ollama"}

    async def _call_ollama_async(self, prompt: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """Direct Ollama call with system context (async)."""
        messages = []
        if context:
            messages.append({"role": "system", "content": json.dumps(context)})
        messages.append({"role": "user", "content": prompt})
        return await self.chat_async(messages)

    def is_available(self) -> bool:
        return self._available

    def analyze(self, prompt: str, context: Optional[Dict] = None, prefer: str = "") -> Dict[str, Any]:
        """Synchronous analyze - calls Ollama directly. No failover needed."""
        self._stats["total_calls"] += 1

        # Check cache
        cache_key = hashlib_sha256(f"{prompt}|{json.dumps(context or {}, sort_keys=True)}")
        cached = self.cache.get(cache_key)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return {**cached, "cached": True}

        if not self._available:
            return {"success": False, "error": "Ollama not available - ensure 'ollama serve' is running", "provider": "ollama"}

        result = self._call_ollama(prompt, context)
        if result.get("success"):
            self.cache.set(cache_key, result)
        return result

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.3,
             max_tokens: int = 4096) -> Dict[str, Any]:
        """Chat completion via Ollama (synchronous)."""
        self._stats["total_calls"] += 1
        if not self._available:
            return {"success": False, "error": "Ollama not available", "provider": "ollama"}

        try:
            import requests as req
            start = time.time()
            payload = {
                "model": self.ollama_model,
                "messages": messages,
                "stream": False,
                "keep_alive": 0,
                "options": {"temperature": temperature, "num_predict": max_tokens},
            }
            resp = req.post(f"{self.ollama_url}/api/chat", json=payload, timeout=180)
            resp.raise_for_status()
            data = resp.json()
            elapsed = time.time() - start

            content = data.get("message", {}).get("content", "")
            self._stats["ollama_calls"] += 1
            self._stats["_total_time"] += elapsed
            self._stats["avg_response_time"] = round(
                self._stats["_total_time"] / max(1, self._stats["ollama_calls"]), 3
            )
            return {
                "success": True,
                "result": content,
                "content": content,
                "provider": "ollama",
                "model": self.ollama_model,
                "duration": round(elapsed, 3),
            }
        except Exception as e:
            self._stats["ollama_failures"] += 1
            return {"success": False, "error": str(e), "provider": "ollama"}

    async def chat(self, messages: List[Dict[str, str]], temperature: float = 0.3,
                   max_tokens: int = 4096) -> Dict[str, Any]:
        """Async chat completion via Ollama."""
        return await self.chat_async(messages, temperature, max_tokens)

    def _call_ollama(self, prompt: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """Direct Ollama call with system context."""
        messages = []
        if context:
            messages.append({"role": "system", "content": json.dumps(context)})
        messages.append({"role": "user", "content": prompt})
        return self.chat(messages)

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "provider": "ollama",
            "ollama_url": self.ollama_url,
            "ollama_model": self.ollama_model,
            "available": self._available,
            "cache_stats": self.cache.stats(),
        }

    def refresh(self):
        """Re-check Ollama availability."""
        self._check_ollama()


def hashlib_sha256(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()
