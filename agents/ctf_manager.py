"""CTF Workflow Manager with category-specific strategies."""

import asyncio
import logging
from enum import Enum
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class CTFCategory(Enum):
    """CTF challenge categories."""
    CRYPTO = "crypto"
    WEB = "web"
    PWN = "pwn"
    FORENSICS = "forensics"
    REVERSE = "reverse"
    MISC = "misc"


class CTFWorkflowManager:
    """Manages CTF challenge solving workflow with AI-assisted strategies."""

    def __init__(self, ai_router: Any):
        self.ai_router = ai_router
        self.solved: List[Dict[str, Any]] = []
        self.strategies = {
            CTFCategory.CRYPTO: self._strategy_crypto,
            CTFCategory.WEB: self._strategy_web,
            CTFCategory.PWN: self._strategy_pwn,
            CTFCategory.FORENSICS: self._strategy_forensics,
            CTFCategory.REVERSE: self._strategy_reverse,
            CTFCategory.MISC: self._strategy_misc,
        }

    async def solve_challenge(
        self,
        challenge_name: str,
        category: CTFCategory,
        description: str,
        attachment_path: Optional[str] = None,
        url: Optional[str] = None,
        points: int = 0
    ) -> Dict[str, Any]:
        """Attempt to solve a CTF challenge using category-specific strategy."""
        logger.info(f"Solving {category.value} challenge: {challenge_name}")

        challenge_info = {
            "name": challenge_name,
            "category": category.value,
            "description": description,
            "attachment_path": attachment_path,
            "url": url,
            "points": points,
        }

        strategy_fn = self.strategies.get(category, self._strategy_misc)
        result = await strategy_fn(challenge_info)

        result["challenge"] = challenge_name
        result["category"] = category.value
        if result.get("flag"):
            self.solved.append({**challenge_info, "flag": result["flag"]})
            logger.info(f"Flag found for {challenge_name}: {result['flag']}")
        else:
            logger.info(f"No flag found for {challenge_name}")

        return result

    async def _strategy_crypto(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """Strategy for cryptography challenges."""
        prompt = (
            f"CTF Crypto Challenge: {challenge['name']}\n"
            f"Description: {challenge['description']}\n"
            f"Analyze this cryptographic challenge. Consider:\n"
            f"- Classical ciphers (Caesar, Vigenere, substitution, transposition)\n"
            f"- Modern crypto (RSA, AES, ECC) weaknesses\n"
            f"- Encoding issues (base64, hex, base32)\n"
            f"- Key reuse, weak PRNG, padding oracle\n"
            f"- Custom/rolled crypto implementations\n"
            f"Provide step-by-step analysis and Python solution code."
        )
        try:
            analysis = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are a CTF crypto challenge expert. Provide working exploit code."
            )
            return {"analysis": analysis, "flag": None, "attempt": "crypto_analysis"}
        except Exception as e:
            logger.error(f"Crypto strategy failed: {e}")
            return {"analysis": f"Error: {e}", "flag": None, "attempt": "crypto_analysis"}

    async def _strategy_web(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """Strategy for web exploitation challenges."""
        url_info = f"URL: {challenge.get('url', 'N/A')}" if challenge.get('url') else ""
        prompt = (
            f"CTF Web Challenge: {challenge['name']}\n"
            f"Description: {challenge['description']}\n"
            f"{url_info}\n"
            f"Analyze this web challenge. Consider:\n"
            f"- SQL injection (union, blind, time-based)\n"
            f"- XSS (reflected, stored, DOM)\n"
            f"- SSRF, CSRF, XXE\n"
            f"- Directory traversal, LFI/RFI\n"
            f"- Cookie/session manipulation\n"
            f"- API abuse, IDOR\n"
            f"- Server-side template injection\n"
            f"Provide curl commands and Python exploit code."
        )
        try:
            analysis = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are a CTF web exploitation expert. Provide working exploit code."
            )
            return {"analysis": analysis, "flag": None, "attempt": "web_analysis"}
        except Exception as e:
            logger.error(f"Web strategy failed: {e}")
            return {"analysis": f"Error: {e}", "flag": None, "attempt": "web_analysis"}

    async def _strategy_pwn(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """Strategy for binary exploitation challenges."""
        prompt = (
            f"CTF Pwn Challenge: {challenge['name']}\n"
            f"Description: {challenge['description']}\n"
            f"Analyze this binary exploitation challenge. Consider:\n"
            f"- Buffer overflow (stack, heap)\n"
            f"- Format string vulnerabilities\n"
            f"- Return-oriented programming (ROP)\n"
            f"- Use-after-free, double-free\n"
            f"- Integer overflow/underflow\n"
            f"- ret2libc, ret2plt\n"
            f"- PIE bypass, ASLR bypass, canary bypass\n"
            f"Provide pwntools exploit code."
        )
        try:
            analysis = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are a CTF binary exploitation expert. Provide pwntools exploit code."
            )
            return {"analysis": analysis, "flag": None, "attempt": "pwn_analysis"}
        except Exception as e:
            logger.error(f"Pwn strategy failed: {e}")
            return {"analysis": f"Error: {e}", "flag": None, "attempt": "pwn_analysis"}

    async def _strategy_forensics(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """Strategy for forensics challenges."""
        prompt = (
            f"CTF Forensics Challenge: {challenge['name']}\n"
            f"Description: {challenge['description']}\n"
            f"Analyze this forensics challenge. Consider:\n"
            f"- File carving and signature analysis\n"
            f"- Steganography (steghide, zsteg, LSB)\n"
            f"- Metadata analysis (exiftool)\n"
            f"- Disk/memory forensics (volatility, sleuth kit)\n"
            f"- Network capture analysis (tshark, Wireshark)\n"
            f"- Log analysis and timeline reconstruction\n"
            f"- PDF/Office document analysis\n"
            f"Provide step-by-step commands and Python scripts."
        )
        try:
            analysis = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are a CTF forensics expert. Provide detailed forensic analysis steps."
            )
            return {"analysis": analysis, "flag": None, "attempt": "forensics_analysis"}
        except Exception as e:
            logger.error(f"Forensics strategy failed: {e}")
            return {"analysis": f"Error: {e}", "flag": None, "attempt": "forensics_analysis"}

    async def _strategy_reverse(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """Strategy for reverse engineering challenges."""
        prompt = (
            f"CTF Reverse Engineering Challenge: {challenge['name']}\n"
            f"Description: {challenge['description']}\n"
            f"Analyze this reverse engineering challenge. Consider:\n"
            f"- Static analysis (Ghidra, IDA, radare2)\n"
            f"- Dynamic analysis (gdb, ltrace, strace)\n"
            f"- Common obfuscation patterns\n"
            f"- String analysis and encoding\n"
            f"- Algorithm identification\n"
            f"- Anti-debugging bypass\n"
            f"- Decompiler output analysis\n"
            f"Provide disassembly annotations and Python solve scripts."
        )
        try:
            analysis = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are a CTF reverse engineering expert. Provide detailed analysis."
            )
            return {"analysis": analysis, "flag": None, "attempt": "reverse_analysis"}
        except Exception as e:
            logger.error(f"Reverse strategy failed: {e}")
            return {"analysis": f"Error: {e}", "flag": None, "attempt": "reverse_analysis"}

    async def _strategy_misc(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """Strategy for miscellaneous challenges."""
        prompt = (
            f"CTF Misc Challenge: {challenge['name']}\n"
            f"Description: {challenge['description']}\n"
            f"Analyze this miscellaneous challenge. Consider:\n"
            f"- Encoding/decoding chains\n"
            f"- OSINT and reconnaissance\n"
            f"- Programming puzzles\n"
            f"- Esoteric languages\n"
            f"- QR codes and visual puzzles\n"
            f"- Blockchain challenges\n"
            f"Provide step-by-step solution approach."
        )
        try:
            analysis = await self.ai_router.query(
                prompt=prompt,
                system_prompt="You are a CTF expert. Provide creative solutions."
            )
            return {"analysis": analysis, "flag": None, "attempt": "misc_analysis"}
        except Exception as e:
            logger.error(f"Misc strategy failed: {e}")
            return {"analysis": f"Error: {e}", "flag": None, "attempt": "misc_analysis"}
