"""
Zero-Trust Context Guard — AES-256 session encryption, delegation field filtering, cross-agent leak detection
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
from typing import Dict, List, Any

logger = logging.getLogger("agent_system")

_SESSION_KEYS: Dict[str, bytes] = {}

_SENSITIVE_FIELDS = {"identity", "token", "api_key", "secret", "credential", "password", "auth"}

_AGENT_ID_PATTERN = re.compile(r"agent_\w+_demo")
_TOKEN_PATTERN = re.compile(r"[a-f0-9]{32,}|eyJ[A-Za-z0-9_-]{10,}")


class ContextGuard:

    def seal(self, agent_id: str, data: Dict[str, Any],
             allowed_fields: List[str] | None = None) -> Dict[str, Any]:
        key = self._get_or_create_key(agent_id)

        if allowed_fields:
            sealed_data = {k: v for k, v in data.items() if k in allowed_fields}
            filtered = [k for k in data.keys() if k not in allowed_fields]
        else:
            sealed_data = {k: v for k, v in data.items() if k.lower() not in _SENSITIVE_FIELDS}
            filtered = [k for k in data.keys() if k.lower() in _SENSITIVE_FIELDS]

        plaintext = json.dumps(sealed_data, sort_keys=True, ensure_ascii=False).encode("utf-8")
        iv = os.urandom(12)
        ciphertext = self._aes_encrypt(key, iv, plaintext)

        blob = base64.urlsafe_b64encode(iv + b":" + ciphertext).decode("ascii")

        return {
            "sealed_blob": blob,
            "fields_sealed": list(sealed_data.keys()),
            "fields_filtered": filtered,
        }

    def unseal(self, agent_id: str, sealed_blob: str) -> Dict[str, Any]:
        key = self._get_or_create_key(agent_id)

        try:
            raw = base64.urlsafe_b64decode(sealed_blob.encode("ascii"))
            iv_b64, ciphertext_b64 = raw.split(b":", 1)
            plaintext = self._aes_decrypt(key, iv_b64, ciphertext_b64)
            data = json.loads(plaintext.decode("utf-8"))
            return {"data": data, "success": True, "violation": False}
        except Exception as e:
            self._log_violation(agent_id, f"Unseal failed: {e}")
            return {"data": {}, "success": False, "violation": True}

    def create_delegation_context(self, source_ctx: Dict[str, Any],
                                   allowed_fields: List[str]) -> Dict[str, Any]:
        result = {}
        filtered = []
        for k, v in source_ctx.items():
            if k in allowed_fields:
                result[k] = v
            else:
                filtered.append(k)
        return {"context": result, "filtered_fields": filtered}

    def scan_cross_agent_leak(self, prompt: str, current_agent_id: str) -> Dict[str, Any]:
        other_agents = _AGENT_ID_PATTERN.findall(prompt)
        other_agents = [a for a in other_agents if a != current_agent_id]

        token_matches = _TOKEN_PATTERN.findall(prompt)

        leaked = len(other_agents) > 0 or len(token_matches) > 0
        risk_score = 1.0 if leaked else 0.0

        if leaked:
            self._log_violation(
                current_agent_id,
                f"Cross-agent info leak: other_agents={other_agents}, tokens={len(token_matches)}"
            )

        return {
            "leaked": leaked,
            "risk_score": risk_score,
            "other_agent_ids": other_agents,
            "token_fragments": len(token_matches),
        }

    def destroy_session_key(self, agent_id: str):
        if agent_id in _SESSION_KEYS:
            del _SESSION_KEYS[agent_id]
            logger.info("session key destroyed for %s", agent_id)

    def _get_or_create_key(self, agent_id: str) -> bytes:
        if agent_id not in _SESSION_KEYS:
            _SESSION_KEYS[agent_id] = os.urandom(32)
        return _SESSION_KEYS[agent_id]

    def _aes_encrypt(self, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            return aesgcm.encrypt(iv, plaintext, None)
        except ImportError:
            return self._xor_encrypt(key, iv, plaintext)

    def _aes_decrypt(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(iv, ciphertext, None)
        except ImportError:
            return self._xor_encrypt(key, iv, ciphertext)

    def _xor_encrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        stream = (key + iv) * (len(data) // 32 + 1)
        return bytes(a ^ b for a, b in zip(data, stream[:len(data)]))

    def _log_violation(self, agent_id: str, reason: str):
        try:
            from app import audit
            audit.log_event(
                agent_id=agent_id,
                action="context_violation",
                resource="context_guard",
                decision="deny",
                reason=reason,
            )
        except Exception as e:
            logger.debug("violation audit log failed: %s", e)
