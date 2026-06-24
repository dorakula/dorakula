#!/usr/bin/env python3
"""Dorakula Sovereign Mode
Offline AI via Ollama for absolute privacy.
What NO competitor has.
"""
import logging
import requests as req
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class SovereignMode:
    """Offline AI mode using Ollama - zero data leaves the machine"""
    
    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "tinyllama:latest"):
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.active = False
        self._available_models = []
    
    def check_availability(self) -> bool:
        try:
            resp = req.get(f"{self.ollama_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                self._available_models = [m.get("name", "") for m in data.get("models", [])]
                if any(self.model in m for m in self._available_models):
                    self.active = True
                    logger.info("Sovereign Mode: Ollama active, model %s available", self.model)
                else:
                    logger.warning("Sovereign Mode: Model %s not found. Available: %s", self.model, self._available_models)
                return True
            return False
        except Exception as e:
            logger.info("Sovereign Mode: Ollama not running at %s - %s", self.ollama_url, e)
            return False
    
    def activate(self) -> Dict[str, Any]:
        if self.check_availability():
            self.active = True
            return {"success": True, "mode": "sovereign", "model": self.model, "url": self.ollama_url}
        return {"success": False, "error": "Ollama not available", "url": self.ollama_url}
    
    def deactivate(self):
        self.active = False
        return {"success": True, "mode": "cloud"}
    
    async def chat(self, messages: list, temperature: float = 0.3) -> Dict[str, Any]:
        if not self.active:
            return {"success": False, "error": "Sovereign mode not active"}
        try:
            payload = {"model": self.model, "messages": messages, "stream": False, "keep_alive": 0, "options": {"temperature": temperature}}
            resp = req.post(f"{self.ollama_url}/api/chat", json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "")
            self._unload_model()
            return {"success": True, "content": content, "provider": "ollama", "model": self.model}
        except Exception as e:
            return {"success": False, "error": str(e)}
    

    def _unload_model(self):
        """Unload model from Ollama RAM after inference."""
        try:
            req.delete(f"{self.ollama_url}/api/generate",
                      json={"model": self.model, "keep_alive": 0}, timeout=5)
        except Exception as e:
            logger.debug("Failed to unload Ollama model: %s", e)

    def get_status(self) -> Dict[str, Any]:
        return {
            "active": self.active,
            "url": self.ollama_url,
            "model": self.model,
            "available_models": self._available_models,
            "privacy_guarantee": "absolute" if self.active else "pending"
        }
