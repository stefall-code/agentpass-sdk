from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, delete, func, desc, and_, Integer

from app.config import settings
from app import database
from app.db import SessionLocal
from app.models import AuditLogRow, AgentRow

# Initialize AgentPass SDK Audit adapter
from app.adapters import get_audit_adapter
_sdk_audit = get_audit_adapter()

logger = logging.getLogger("agent_system")

_CHAIN_HASH_CACHE: str | None = None


def _get_last_chain_hash() -> str:
    global _CHAIN_HASH_CACHE
    if _CHAIN_HASH_CACHE is not None:
        return _CHAIN_HASH_CACHE
    with SessionLocal() as db:
        row = db.execute(
            select(AuditLogRow).order_by(desc(AuditLogRow.id)).limit(1)
        ).scalar_one_or_none()
        if row:
            try:
                ctx = json.loads(row.context_json or "{}")
                _CHAIN_HASH_CACHE = ctx.get("_chain_hash", "genesis")
            except (json.JSONDecodeError, TypeError):
                _CHAIN_HASH_CACHE = "genesis"
        else:
            _CHAIN_HASH_CACHE = "genesis"
    return _CHAIN_HASH_CACHE


def _compute_chain_hash(log_id: int, agent_id: str | None, action: str,
                        resource: str, decision: str, reason: str,
                        created_at: str, prev_hash: str) -> str:
    payload = json.dumps({
        "id": log_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason,
        "created_at": created_at,
        "prev_hash": prev_hash,
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def log_event(
    action: str,
    resource: str,
    decision: str,
    reason: str,
    agent_id: str | None = None,
    ip_address: str | None = None,
    token_id: str | None = None,
    context: dict | None = None,
    six_layer: dict | None = None,
) -> None:
    global _CHAIN_HASH_CACHE
    now = database.utc_now()
    context = context or {}

    if six_layer:
        context["_six_layer"] = six_layer
    else:
        try:
            from app.security.six_layer_verify import verify_six_layers
            trust_score = context.get("trust_score", 0.5)
            risk_score = context.get("risk_score", 0.0)
            role = context.get("role", "basic")
            chain = context.get("delegation_chain", [agent_id] if agent_id else [])
            v = verify_six_layers(
                agent_id=agent_id or "unknown",
                action=f"{action}:{resource}" if resource else action,
                input_text=context.get("input_text", ""),
                trust_score=trust_score,
                risk_score=risk_score,
                role=role,
                delegation_chain=chain,
                allowed=(decision == "allow"),
                blocked_at="" if decision == "allow" else "iam_gateway",
                auto_revoked=context.get("auto_revoked", False),
                reason=reason,
            )
            context["_six_layer"] = {
                "overall": v.overall_status,
                "decision": v.final_decision,
                "layers": {
                    l.layer_id: {"name": l.layer_name, "status": l.status, "detail": l.detail}
                    for l in v.layers
                },
            }
        except Exception:
            pass

    # Write to SDK Audit (in-memory, for future export)
    try:
        _sdk_audit.log_event(
            event_type=action,
            agent_id=agent_id,
            resource=resource,
            action=action,
            status=decision,
            ip_address=ip_address,
            token_id=token_id,
            context=context
        )
    except Exception as sdk_err:
        logger.warning(f"SDK Audit logging failed: {sdk_err}")

    prev_hash = _get_last_chain_hash()

    with SessionLocal() as db:
        row = AuditLogRow(
            agent_id=agent_id,
            action=action,
            resource=resource,
            decision=decision,
            reason=reason,
            ip_address=ip_address,
            token_id=token_id,
            created_at=now,
            context_json=json.dumps(context, ensure_ascii=False),
        )
        db.add(row)
        db.flush()

        chain_hash = _compute_chain_hash(
            row.id, agent_id, action, resource, decision, reason, now, prev_hash
        )
        context["_chain_hash"] = chain_hash
        row.context_json = json.dumps(context, ensure_ascii=False)
        db.commit()
        _CHAIN_HASH_CACHE = chain_hash

    try:
        from app.ws import ws_manager
        event = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
            "ip_address": ip_address,
            "created_at": now,
            "context": context,
        }
        ws_manager.emit_audit(event)
    except ImportError:
        pass

    if decision == "deny" and agent_id:
        _maybe_lock_agent(agent_id)


def _maybe_lock_agent(agent_id: str) -> None:
    since = (datetime.now(timezone.utc) - timedelta(minutes=settings.DENIAL_WINDOW_MINUTES)).isoformat()
    with SessionLocal() as db:
        denial_count = db.execute(
            select(func.count()).select_from(AuditLogRow)
            .where(and_(AuditLogRow.agent_id == agent_id, AuditLogRow.decision == "deny", AuditLogRow.created_at >= since))
        ).scalar() or 0

        agent_row = db.get(AgentRow, agent_id)
        if not agent_row:
            return
        if agent_row.role == "admin":
            return

        if denial_count >= settings.DENIAL_LOCK_THRESHOLD and agent_row.status == "active":
            agent_row.status = "suspended"
            agent_row.status_reason = "Automatically suspended after repeated denied requests."
            agent_row.updated_at = database.utc_now()
            db.commit()

            try:
                from app.services.reputation_service import ReputationEngine
                ReputationEngine().compute_score(agent_id)
            except Exception:
                pass


def fetch_logs(limit: int = 20, agent_id: str | None = None) -> list[dict]:
    return fetch_logs_filtered(limit=limit, agent_id=agent_id)


def fetch_logs_filtered(
    limit: int = 20,
    agent_id: str | None = None,
    decision: str | None = None,
    action: str | None = None,
) -> list[dict]:
    with SessionLocal() as db:
        q = select(AuditLogRow).order_by(desc(AuditLogRow.id))
        if agent_id:
            q = q.where(AuditLogRow.agent_id == agent_id)
        if decision:
            q = q.where(AuditLogRow.decision == decision)
        if action:
            q = q.where(AuditLogRow.action == action)
        rows = db.execute(q.limit(limit)).scalars().all()

    results = []
    for row in rows:
        item = {
            "id": row.id,
            "agent_id": row.agent_id,
            "action": row.action,
            "resource": row.resource,
            "decision": row.decision,
            "reason": row.reason,
            "ip_address": row.ip_address,
            "token_id": row.token_id,
            "created_at": row.created_at,
            "context": json.loads(row.context_json or "{}"),
        }
        results.append(item)
    return results


def clear_logs() -> int:
    with SessionLocal() as db:
        count = db.execute(select(func.count()).select_from(AuditLogRow)).scalar() or 0
        db.execute(delete(AuditLogRow))
        db.commit()
    _sdk_audit.clear_events()
    return count


def get_audit_summary() -> dict:
    with SessionLocal() as db:
        totals = db.execute(
            select(
                func.count().label("total"),
                func.sum(func.cast(AuditLogRow.decision == "allow", type_=Integer)).label("allow_count"),
                func.sum(func.cast(AuditLogRow.decision == "deny", type_=Integer)).label("deny_count"),
            ).select_from(AuditLogRow)
        ).first()

        top_actions = db.execute(
            select(AuditLogRow.action, func.count().label("count"))
            .group_by(AuditLogRow.action)
            .order_by(desc("count"), AuditLogRow.action)
            .limit(6)
        ).all()

    return {
        "total": totals[0] or 0,
        "allow": int(totals[1] or 0),
        "deny": int(totals[2] or 0),
        "top_actions": [
            {"action": r[0], "count": r[1]}
            for r in top_actions
        ],
        "recent_denials": fetch_logs_filtered(limit=6, decision="deny"),
    }


def export_audit_to_json(file_path: str | None = None) -> str:
    return _sdk_audit.export_to_json(file_path)


def export_audit_to_csv(file_path: str | None = None) -> str:
    return _sdk_audit.export_to_csv(file_path)


def get_sdk_audit_events(filters: dict | None = None, limit: int = 100) -> list[dict]:
    return _sdk_audit.get_events(filters, limit)


def get_sdk_audit_all_events() -> list[dict]:
    return _sdk_audit.get_all_events()


def verify_chain_integrity() -> dict:
    """验证审计日志哈希链完整性"""
    with SessionLocal() as db:
        rows = db.execute(
            select(AuditLogRow).order_by(AuditLogRow.id.asc())
        ).scalars().all()

    if not rows:
        return {"valid": True, "total_logs": 0, "verified": 0, "broken_at": None, "message": "No audit logs to verify"}

    prev_hash = "genesis"
    broken_at = None
    verified = 0

    for row in rows:
        try:
            ctx = json.loads(row.context_json or "{}")
            stored_hash = ctx.get("_chain_hash", "")
        except (json.JSONDecodeError, TypeError):
            stored_hash = ""

        expected_hash = _compute_chain_hash(
            row.id, row.agent_id, row.action, row.resource,
            row.decision, row.reason, row.created_at, prev_hash
        )

        if stored_hash != expected_hash:
            broken_at = row.id
            break

        prev_hash = stored_hash
        verified += 1

    return {
        "valid": broken_at is None,
        "total_logs": len(rows),
        "verified": verified,
        "broken_at": broken_at,
        "message": "Hash chain integrity verified" if broken_at is None else f"Chain broken at log id={broken_at}",
    }


def get_sdk_audit_count() -> int:
    return _sdk_audit.get_event_count()
