from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Set

import jwt

from app.config import settings
from app.policy.dynamic_policy import evaluate_dynamic_policy

MAX_CHAIN_DEPTH = 5

CAPABILITY_AGENTS: Dict[str, Dict[str, Any]] = {
    "doc_agent": {
        "capabilities": ["write:doc:public", "delegate:data_agent"],
        "description": "Document Agent — can write public docs and delegate to data_agent",
    },
    "data_agent": {
        "capabilities": ["read:feishu_table", "read:feishu_table:finance", "read:feishu_table:hr"],
        "description": "Data Agent — can read Feishu tables (finance, HR, and general)",
    },
    "external_agent": {
        "capabilities": ["read:web"],
        "description": "External Agent — can read web resources only",
    },
}

USED_TOKENS: Set[str] = set()

REVOKED_TOKENS: Set[str] = set()
REVOKED_USERS: Dict[str, str] = {}
REVOKED_AGENTS: Dict[str, str] = {}

AGENT_TRUST_SCORE: Dict[str, float] = {
    "doc_agent": 0.9,
    "data_agent": 0.95,
    "external_agent": 0.6,
}

TRUST_THRESHOLD = 0.5
TRUST_REWARD = 0.01
TRUST_PENALTY_DENY = 0.05
TRUST_PENALTY_ESCALATION = 0.1
AUTO_REVOKE_THRESHOLD = 0.3

AUTO_REVOKED_AGENTS: Dict[str, Dict[str, Any]] = {}


def mark_token_used(jti: str) -> None:
    USED_TOKENS.add(jti)


def is_token_used(jti: str) -> bool:
    return jti in USED_TOKENS


def clear_used_tokens() -> int:
    count = len(USED_TOKENS)
    USED_TOKENS.clear()
    return count


def revoke_token_by_jti(jti: str) -> None:
    REVOKED_TOKENS.add(jti)


def revoke_tokens_by_user(user: str, reason: str = "") -> int:
    REVOKED_USERS[user] = reason or f"Revoked by admin for user={user}"
    return 1


def revoke_tokens_by_agent(agent_id: str, reason: str = "") -> int:
    REVOKED_AGENTS[agent_id] = reason or f"Revoked by admin for agent={agent_id}"
    return 1


def is_token_revoked(claims: Dict[str, Any]) -> tuple[bool, str]:
    jti = claims.get("jti", "")
    if jti and jti in REVOKED_TOKENS:
        return True, f"Token revoked (jti={jti[:8]}...)"

    delegated_user = claims.get("delegated_user", "")
    if delegated_user and delegated_user in REVOKED_USERS:
        return True, f"Token revoked: user '{delegated_user}' is revoked ({REVOKED_USERS[delegated_user]})"

    agent_id = claims.get("agent_id", "")
    if agent_id and agent_id in REVOKED_AGENTS:
        return True, f"Token revoked: agent '{agent_id}' is revoked ({REVOKED_AGENTS[agent_id]})"

    return False, ""


def clear_revoked() -> int:
    count = len(REVOKED_TOKENS) + len(REVOKED_USERS) + len(REVOKED_AGENTS)
    REVOKED_TOKENS.clear()
    REVOKED_USERS.clear()
    REVOKED_AGENTS.clear()
    return count


def get_revoked_list() -> Dict[str, Any]:
    return {
        "revoked_jtis": sorted(REVOKED_TOKENS),
        "revoked_users": dict(REVOKED_USERS),
        "revoked_agents": dict(REVOKED_AGENTS),
        "total": len(REVOKED_TOKENS) + len(REVOKED_USERS) + len(REVOKED_AGENTS),
    }


def get_trust_score(agent_id: str) -> float:
    return AGENT_TRUST_SCORE.get(agent_id, 0.5)


def update_trust_score(agent_id: str, delta: float) -> tuple[float, float]:
    before = AGENT_TRUST_SCORE.get(agent_id, 0.5)
    after = max(0.0, min(1.0, before + delta))
    AGENT_TRUST_SCORE[agent_id] = after
    return before, after


def get_all_trust_scores() -> Dict[str, Any]:
    scores = {}
    for agent_id in CAPABILITY_AGENTS:
        scores[agent_id] = {
            "trust_score": AGENT_TRUST_SCORE.get(agent_id, 0.5),
            "status": "trusted" if AGENT_TRUST_SCORE.get(agent_id, 0.5) >= TRUST_THRESHOLD else "untrusted",
            "capabilities": CAPABILITY_AGENTS[agent_id]["capabilities"],
        }
    for agent_id, score in AGENT_TRUST_SCORE.items():
        if agent_id not in scores:
            scores[agent_id] = {
                "trust_score": score,
                "status": "trusted" if score >= TRUST_THRESHOLD else "untrusted",
                "capabilities": [],
            }
    return {"agents": scores, "threshold": TRUST_THRESHOLD}


def reset_trust_scores() -> Dict[str, float]:
    defaults = {"doc_agent": 0.9, "data_agent": 0.95, "external_agent": 0.6}
    for agent_id, score in defaults.items():
        AGENT_TRUST_SCORE[agent_id] = score
    for agent_id in list(AGENT_TRUST_SCORE.keys()):
        if agent_id not in defaults:
            AGENT_TRUST_SCORE[agent_id] = 0.5
    return dict(AGENT_TRUST_SCORE)


def auto_revoke_agent(agent_id: str, reason: str = "") -> Dict[str, Any]:
    revoke_tokens_by_agent(agent_id, reason or f"Auto revoke: trust score below {AUTO_REVOKE_THRESHOLD}")
    trust_before = AGENT_TRUST_SCORE.get(agent_id, 0.5)
    AGENT_TRUST_SCORE[agent_id] = 0.0
    AUTO_REVOKED_AGENTS[agent_id] = {
        "reason": reason or f"Auto revoke: trust score {trust_before:.2f} < threshold {AUTO_REVOKE_THRESHOLD}",
        "trust_score_at_revoke": trust_before,
        "revoked_at": datetime.now(timezone.utc).isoformat(),
    }
    return {
        "agent_id": agent_id,
        "auto_revoked": True,
        "reason": AUTO_REVOKED_AGENTS[agent_id]["reason"],
        "trust_score_before": trust_before,
        "trust_score_after": 0.0,
    }


def is_agent_auto_revoked(agent_id: str) -> tuple[bool, str]:
    if agent_id in AUTO_REVOKED_AGENTS:
        return True, AUTO_REVOKED_AGENTS[agent_id]["reason"]
    return False, ""


def clear_auto_revoked() -> int:
    count = len(AUTO_REVOKED_AGENTS)
    AUTO_REVOKED_AGENTS.clear()
    return count


def get_auto_revoked_list() -> Dict[str, Any]:
    return {
        "auto_revoked_agents": dict(AUTO_REVOKED_AGENTS),
        "threshold": AUTO_REVOKE_THRESHOLD,
        "total": len(AUTO_REVOKED_AGENTS),
    }


@dataclass
class DelegationResult:
    success: bool
    token: Optional[str] = None
    claims: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


@dataclass
class CheckResult:
    allowed: bool
    reason: str
    chain: List[str]
    delegated_user: Optional[str] = None
    capabilities: Optional[List[str]] = None
    risk_score: float = 0.0
    jti: Optional[str] = None
    auto_revoked: bool = False


class DelegationEngine:

    @staticmethod
    def _parse_capability(cap: str) -> tuple[str, str, str]:
        parts = cap.split(":")
        action = parts[0] if len(parts) > 0 else ""
        resource = parts[1] if len(parts) > 1 else ""
        scope = parts[2] if len(parts) > 2 else ""
        return action, resource, scope

    @staticmethod
    def _match_capability(requested: str, granted: str) -> bool:
        if requested == granted:
            return True
        req_parts = requested.split(":")
        gra_parts = granted.split(":")
        if len(req_parts) < 2 or len(gra_parts) < 2:
            return False
        if gra_parts[0] != req_parts[0]:
            return False
        if gra_parts[1] != req_parts[1]:
            return False
        if len(gra_parts) >= 3 and gra_parts[2] == "*":
            return True
        if len(req_parts) >= 3 and len(gra_parts) >= 3:
            return gra_parts[2] == req_parts[2]
        if len(req_parts) == 2 and len(gra_parts) == 2:
            return True
        return False

    def _check_capability(self, action: str, capabilities: List[str]) -> tuple[bool, str]:
        for cap in capabilities:
            if self._match_capability(action, cap):
                return True, f"Matched capability: {cap}"
        req_action, req_resource, req_scope = self._parse_capability(action)
        if req_scope:
            wildcard = f"{req_action}:{req_resource}:*"
            for cap in capabilities:
                if cap == wildcard:
                    return True, f"Matched wildcard capability: {cap}"
        return False, f"resource scope not allowed: '{action}' not in {capabilities}"

    def _build_payload(
        self,
        agent_id: str,
        delegated_user: str,
        capabilities: List[str],
        parent_agent: str,
        chain: List[str],
        exp: datetime,
        chain_detail: Optional[List[Dict[str, str]]] = None,
        delegation_action: str = "",
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        detail = list(chain_detail) if chain_detail else []
        if not detail:
            detail = [{"agent": "user", "action": "initiate", "capability": ""}]
        if agent_id != "user":
            last_action = delegation_action or "delegate"
            detail.append({
                "agent": agent_id,
                "action": last_action,
                "capability": ", ".join(capabilities) if capabilities else "",
            })
        return {
            "agent_id": agent_id,
            "delegated_user": delegated_user,
            "capabilities": capabilities,
            "parent_agent": parent_agent,
            "chain": chain,
            "chain_detail": detail,
            "type": "delegation",
            "jti": str(uuid.uuid4()),
            "nonce": secrets.token_hex(16),
            "iat": int(now.timestamp()),
            "issued_at": now.isoformat(),
            "exp": int(exp.timestamp()),
            "used": False,
            "bind_agent": agent_id,
        }

    def issue_root_token(
        self,
        agent_id: str,
        delegated_user: str,
        capabilities: List[str],
        expires_in_minutes: int = 60,
        metadata: Dict[str, Any] = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=expires_in_minutes)
        payload = self._build_payload(
            agent_id=agent_id,
            delegated_user=delegated_user,
            capabilities=capabilities,
            parent_agent="user",
            chain=["user", agent_id],
            exp=exp,
            delegation_action="start",
        )
        if metadata:
            payload["metadata"] = metadata
        return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    def decode_delegation_token(self, token: str) -> Dict[str, Any]:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])

    def validate_chain(self, claims: Dict[str, Any]) -> tuple[bool, str]:
        chain: List[str] = claims.get("chain", [])
        agent_id: str = claims.get("agent_id", "")
        parent_agent: str = claims.get("parent_agent", "")
        delegated_user: str = claims.get("delegated_user", "")

        if not chain:
            return False, "Chain is empty"

        if len(chain) < 2:
            return False, "Chain must contain at least user + agent"

        if chain[0] != "user":
            return False, "Chain must start with 'user'"

        if chain[-1] != agent_id:
            return False, f"Chain last element must equal agent_id ({agent_id})"

        if len(chain) != len(set(chain)):
            return False, "Chain contains duplicate entries (cycle detected)"

        if parent_agent != chain[-2]:
            return False, f"parent_agent ({parent_agent}) must equal chain[-2] ({chain[-2]})"

        if len(chain) > MAX_CHAIN_DEPTH:
            return False, f"Chain depth exceeds maximum ({MAX_CHAIN_DEPTH})"

        if not delegated_user:
            return False, "delegated_user is required"

        return True, "Chain valid"

    def _check_replay(self, claims: Dict[str, Any]) -> tuple[bool, str]:
        jti = claims.get("jti", "")
        if not jti:
            return False, "Token missing jti (not a valid delegation token)"

        if is_token_used(jti):
            return False, f"Replay attack detected: token already used (jti={jti[:8]}...)"

        return True, "OK"

    def _check_bind_agent(self, claims: Dict[str, Any], caller_agent: str) -> tuple[bool, str]:
        bind_agent = claims.get("bind_agent", "")
        if not bind_agent:
            return True, "No bind_agent constraint"

        if bind_agent != caller_agent:
            return False, f"Agent binding mismatch: token bound to '{bind_agent}' but caller is '{caller_agent}'"

        return True, "OK"

    def delegate(
        self,
        parent_token: str,
        target_agent: str,
        action: str,
        caller_agent: str = "",
    ) -> DelegationResult:
        try:
            parent_claims = self.decode_delegation_token(parent_token)
        except jwt.ExpiredSignatureError:
            return DelegationResult(success=False, reason="Parent token expired")
        except jwt.InvalidTokenError:
            return DelegationResult(success=False, reason="Invalid parent token")

        if parent_claims.get("type") != "delegation":
            return DelegationResult(success=False, reason="Token is not a delegation token")

        revoked, revoke_reason = is_token_revoked(parent_claims)
        if revoked:
            return DelegationResult(success=False, reason=revoke_reason)

        replay_ok, replay_reason = self._check_replay(parent_claims)
        if not replay_ok:
            return DelegationResult(success=False, reason=replay_reason)

        parent_agent_id = parent_claims.get("agent_id", "")
        effective_caller = caller_agent or parent_agent_id
        bind_ok, bind_reason = self._check_bind_agent(parent_claims, effective_caller)
        if not bind_ok:
            return DelegationResult(success=False, reason=bind_reason)

        chain_valid, chain_reason = self.validate_chain(parent_claims)
        if not chain_valid:
            return DelegationResult(success=False, reason=f"Parent chain invalid: {chain_reason}")

        if target_agent not in CAPABILITY_AGENTS:
            return DelegationResult(success=False, reason=f"Unknown target agent: {target_agent}")

        parent_caps: Set[str] = set(parent_claims.get("capabilities", []))
        target_caps: Set[str] = set(CAPABILITY_AGENTS[target_agent]["capabilities"])

        delegate_cap = f"delegate:{target_agent}"
        has_delegate_cap = any(self._match_capability(delegate_cap, c) for c in parent_caps)
        if not has_delegate_cap:
            return DelegationResult(
                success=False,
                reason=f"Parent agent '{parent_claims['agent_id']}' lacks capability '{delegate_cap}' to delegate to '{target_agent}'",
            )

        parent_action_caps = {c for c in parent_caps if not c.startswith("delegate:")}
        target_action_caps = {c for c in target_caps if not c.startswith("delegate:")}
        target_delegate_caps = {c for c in target_caps if c.startswith("delegate:")}

        action_overlap = parent_action_caps & target_action_caps
        if action_overlap:
            effective_caps = action_overlap
        else:
            effective_caps = target_action_caps

        effective_caps = effective_caps | target_delegate_caps

        new_chain = list(parent_claims.get("chain", [])) + [target_agent]

        chain_valid, chain_reason = self.validate_chain({
            "chain": new_chain,
            "agent_id": target_agent,
            "parent_agent": parent_claims["agent_id"],
            "delegated_user": parent_claims.get("delegated_user", ""),
        })
        if not chain_valid:
            return DelegationResult(success=False, reason=f"New chain invalid: {chain_reason}")

        now = datetime.now(timezone.utc)
        parent_exp = datetime.fromtimestamp(parent_claims["exp"], tz=timezone.utc)
        new_exp = min(parent_exp, now + timedelta(hours=1))

        child_payload = self._build_payload(
            agent_id=target_agent,
            delegated_user=parent_claims["delegated_user"],
            capabilities=sorted(effective_caps),
            parent_agent=parent_claims["agent_id"],
            chain=new_chain,
            exp=new_exp,
            chain_detail=parent_claims.get("chain_detail"),
            delegation_action=f"delegate:{action}",
        )

        child_token = jwt.encode(child_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

        mark_token_used(parent_claims["jti"])

        return DelegationResult(
            success=True,
            token=child_token,
            claims=child_payload,
            reason=f"Delegated to {target_agent} with capabilities: {sorted(effective_caps)}",
        )

    def check(
        self,
        token: str,
        action: str,
        resource: str = "",
        caller_agent: str = "",
    ) -> CheckResult:
        try:
            claims = self.decode_delegation_token(token)
        except jwt.ExpiredSignatureError:
            return CheckResult(allowed=False, reason="Token expired", chain=[], risk_score=1.0)
        except jwt.InvalidTokenError:
            return CheckResult(allowed=False, reason="Invalid token", chain=[], risk_score=1.0)

        if claims.get("type") != "delegation":
            return CheckResult(allowed=False, reason="Not a delegation token", chain=[], risk_score=0.8)

        jti = claims.get("jti", "")
        chain = claims.get("chain", [])
        delegated_user = claims.get("delegated_user")
        capabilities: List[str] = claims.get("capabilities", [])
        agent_id = claims.get("agent_id", "")

        auto_revoked, auto_revoke_reason = is_agent_auto_revoked(agent_id)
        if auto_revoked:
            return CheckResult(
                allowed=False,
                reason=f"Agent auto-revoked: {auto_revoke_reason}",
                chain=chain,
                delegated_user=delegated_user,
                capabilities=capabilities,
                risk_score=1.0,
                jti=jti,
                auto_revoked=True,
            )

        revoked, revoke_reason = is_token_revoked(claims)
        if revoked:
            return CheckResult(
                allowed=False,
                reason=revoke_reason,
                chain=chain,
                delegated_user=delegated_user,
                capabilities=capabilities,
                risk_score=1.0,
                jti=jti,
            )

        replay_ok, replay_reason = self._check_replay(claims)
        if not replay_ok:
            update_trust_score(agent_id, -TRUST_PENALTY_ESCALATION)
            trust_after_replay = get_trust_score(agent_id)
            if trust_after_replay < AUTO_REVOKE_THRESHOLD:
                auto_revoke_agent(agent_id, reason=f"Auto revoke: replay attack detected, trust={trust_after_replay:.2f}")
                return CheckResult(
                    allowed=False,
                    reason=f"Replay attack detected → Agent auto-revoked (trust={trust_after_replay:.2f})",
                    chain=chain,
                    delegated_user=delegated_user,
                    capabilities=capabilities,
                    risk_score=1.0,
                    jti=jti,
                    auto_revoked=True,
                )
            return CheckResult(
                allowed=False,
                reason=replay_reason,
                chain=chain,
                delegated_user=delegated_user,
                capabilities=capabilities,
                risk_score=1.0,
                jti=jti,
            )

        token_agent = claims.get("agent_id", "")
        effective_caller = caller_agent or token_agent
        bind_ok, bind_reason = self._check_bind_agent(claims, effective_caller)
        if not bind_ok:
            return CheckResult(
                allowed=False,
                reason=bind_reason,
                chain=chain,
                delegated_user=delegated_user,
                capabilities=capabilities,
                risk_score=0.9,
                jti=jti,
            )

        chain_valid, chain_reason = self.validate_chain(claims)
        if not chain_valid:
            return CheckResult(
                allowed=False,
                reason=f"Chain validation failed: {chain_reason}",
                chain=chain,
                delegated_user=delegated_user,
                capabilities=capabilities,
                risk_score=0.9,
                jti=jti,
            )

        cap_ok, cap_reason = self._check_capability(action, capabilities)
        if not cap_ok:
            update_trust_score(agent_id, -TRUST_PENALTY_ESCALATION)
            trust_after_esc = get_trust_score(agent_id)
            if trust_after_esc < AUTO_REVOKE_THRESHOLD:
                auto_revoke_agent(agent_id, reason=f"Auto revoke: repeated escalation, trust={trust_after_esc:.2f}")
                return CheckResult(
                    allowed=False,
                    reason=f"Privilege escalation → Agent auto-revoked (trust={trust_after_esc:.2f})",
                    chain=chain,
                    delegated_user=delegated_user,
                    capabilities=capabilities,
                    risk_score=1.0,
                    jti=jti,
                    auto_revoked=True,
                )
            return CheckResult(
                allowed=False,
                reason=cap_reason,
                chain=chain,
                delegated_user=delegated_user,
                capabilities=capabilities,
                risk_score=0.7,
                jti=jti,
            )

        dynamic_context = {
            "agent_id": agent_id,
            "user": delegated_user or "",
            "action": action,
            "resource": resource,
            "risk_score": 0.0,
            "timestamp": claims.get("issued_at", ""),
            "chain_length": len(chain),
        }
        dynamic_result = evaluate_dynamic_policy(dynamic_context)
        if not dynamic_result.allowed:
            update_trust_score(agent_id, -TRUST_PENALTY_DENY)
            trust_after_deny = get_trust_score(agent_id)
            if trust_after_deny < AUTO_REVOKE_THRESHOLD:
                auto_revoke_agent(agent_id, reason=f"Auto revoke: repeated dynamic policy deny, trust={trust_after_deny:.2f}")
                return CheckResult(
                    allowed=False,
                    reason=f"Dynamic policy deny → Agent auto-revoked (trust={trust_after_deny:.2f})",
                    chain=chain,
                    delegated_user=delegated_user,
                    capabilities=capabilities,
                    risk_score=1.0,
                    jti=jti,
                    auto_revoked=True,
                )
            return CheckResult(
                allowed=False,
                reason=dynamic_result.reason,
                chain=chain,
                delegated_user=delegated_user,
                capabilities=capabilities,
                risk_score=0.8,
                jti=jti,
            )

        trust_score = get_trust_score(agent_id)
        if trust_score < TRUST_THRESHOLD:
            update_trust_score(agent_id, -TRUST_PENALTY_DENY)
            trust_after_low = get_trust_score(agent_id)
            if trust_after_low < AUTO_REVOKE_THRESHOLD:
                auto_revoke_agent(agent_id, reason=f"Auto revoke: low trust score, trust={trust_after_low:.2f}")
                return CheckResult(
                    allowed=False,
                    reason=f"Low trust score → Agent auto-revoked (trust={trust_after_low:.2f})",
                    chain=chain,
                    delegated_user=delegated_user,
                    capabilities=capabilities,
                    risk_score=1.0,
                    jti=jti,
                    auto_revoked=True,
                )
            return CheckResult(
                allowed=False,
                reason=f"Low trust score: agent '{agent_id}' trust={trust_score:.2f} < threshold={TRUST_THRESHOLD}",
                chain=chain,
                delegated_user=delegated_user,
                capabilities=capabilities,
                risk_score=0.85,
                jti=jti,
            )

        mark_token_used(jti)

        update_trust_score(agent_id, TRUST_REWARD)

        return CheckResult(
            allowed=True,
            reason=f"Action '{action}' allowed via chain {' → '.join(chain)}",
            chain=chain,
            delegated_user=delegated_user,
            capabilities=capabilities,
            risk_score=0.1,
            jti=jti,
        )

    def introspect(self, token: str) -> Dict[str, Any]:
        try:
            claims = self.decode_delegation_token(token)
        except jwt.ExpiredSignatureError:
            return {"active": False, "reason": "Token expired"}
        except jwt.InvalidTokenError:
            return {"active": False, "reason": "Invalid token"}

        jti = claims.get("jti", "")
        chain_valid, chain_reason = self.validate_chain(claims)
        revoked, revoke_reason = is_token_revoked(claims)
        return {
            "active": chain_valid and not is_token_used(jti) and not revoked,
            "agent_id": claims.get("agent_id"),
            "delegated_user": claims.get("delegated_user"),
            "capabilities": claims.get("capabilities", []),
            "parent_agent": claims.get("parent_agent"),
            "chain": claims.get("chain", []),
            "chain_detail": claims.get("chain_detail", []),
            "chain_valid": chain_valid,
            "chain_reason": chain_reason,
            "type": claims.get("type"),
            "exp": claims.get("exp"),
            "jti": jti,
            "nonce": claims.get("nonce"),
            "issued_at": claims.get("issued_at"),
            "bind_agent": claims.get("bind_agent"),
            "used": is_token_used(jti),
            "revoked": revoked,
            "revoke_reason": revoke_reason if revoked else None,
        }
