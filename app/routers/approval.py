from __future__ import annotations

import json
import logging
import os
from datetime import timedelta, timezone, datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from sqlalchemy import select, func

from app import audit, database
from app.auth import AuthContext
from app.config import settings
from app.db import SessionLocal
from app.models import ApprovalRequest
from app.dependencies import require_admin_permission

logger = logging.getLogger("agent_system")
approval_router = APIRouter(prefix="/admin/approvals", tags=["Approval"])


class ApprovalDecisionRequest(BaseModel):
    decision: str = Field(..., pattern="^(approved|denied)$")
    reason: str = ""


class ApprovalResponse(BaseModel):
    id: int
    agent_id: str
    action: str
    resource: str
    risk_score: float
    status: str
    requested_at: str
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    reason: Optional[str] = None


class FeishuCallbackRequest(BaseModel):
    approval_id: int
    decision: str = Field(..., pattern="^(approved|denied)$")
    operator: str = "feishu_user"


@approval_router.get("", response_model=List[ApprovalResponse])
def list_approvals(
    status_filter: str = Query(default="pending", alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    context: AuthContext = Depends(require_admin_permission("view_audit", "admin:approvals")),
) -> List[ApprovalResponse]:
    with SessionLocal() as db:
        q = select(ApprovalRequest).order_by(ApprovalRequest.id.desc())
        if status_filter and status_filter != "all":
            q = q.where(ApprovalRequest.status == status_filter)
        rows = db.execute(q.limit(limit)).scalars().all()
    return [
        ApprovalResponse(
            id=r.id, agent_id=r.agent_id, action=r.action,
            resource=r.resource, risk_score=r.risk_score,
            status=r.status, requested_at=r.requested_at,
            decided_at=r.decided_at, decided_by=r.decided_by,
            reason=r.reason,
        )
        for r in rows
    ]


@approval_router.post("/{approval_id}/decide", response_model=ApprovalResponse)
def decide_approval(
    approval_id: int,
    payload: ApprovalDecisionRequest,
    context: AuthContext = Depends(require_admin_permission("manage_agents", "admin:approvals")),
) -> ApprovalResponse:
    with SessionLocal() as db:
        row = db.execute(
            select(ApprovalRequest).where(ApprovalRequest.id == approval_id)
        ).scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Approval request not found")
        if row.status != "pending":
            raise HTTPException(status_code=400, detail=f"Already {row.status}")

        now = database.utc_now()
        row.status = payload.decision
        row.decided_at = now
        row.decided_by = context.agent["agent_id"]
        row.reason = payload.reason
        db.commit()
        db.refresh(row)

    audit.log_event(
        agent_id=row.agent_id,
        action=f"approval_{payload.decision}",
        resource=row.resource,
        decision="allow" if payload.decision == "approved" else "deny",
        reason=f"HitL: {payload.reason or payload.decision} by {context.agent['agent_id']}",
        ip_address=context.request_ip,
        token_id=context.token_id,
    )

    _ws_notify(row, payload.decision)
    return ApprovalResponse(
        id=row.id, agent_id=row.agent_id, action=row.action,
        resource=row.resource, risk_score=row.risk_score,
        status=row.status, requested_at=row.requested_at,
        decided_at=row.decided_at, decided_by=row.decided_by,
        reason=row.reason,
    )


@approval_router.get("/pending-count")
def pending_count(
    context: AuthContext = Depends(require_admin_permission("view_audit", "admin:approvals")),
) -> Dict[str, int]:
    with SessionLocal() as db:
        count = db.execute(
            select(func.count()).select_from(ApprovalRequest)
            .where(ApprovalRequest.status == "pending")
        ).scalar() or 0
    return {"pending_count": count}


def create_approval_request(agent_id: str, action: str, resource: str,
                            risk_score: float, payload: dict | None = None) -> ApprovalRequest:
    now = datetime.now(timezone.utc)
    timeout_at = (now + timedelta(minutes=settings.APPROVAL_TIMEOUT_MINUTES)).strftime("%Y-%m-%dT%H:%M:%SZ")

    with SessionLocal() as db:
        row = ApprovalRequest(
            agent_id=agent_id,
            action=action,
            resource=resource,
            risk_score=risk_score,
            payload_json=json.dumps(payload or {}),
            status="pending",
            requested_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            timeout_at=timeout_at,
        )
        db.add(row)
        db.commit()
        db.refresh(row)

    _send_feishu_card(row)
    _ws_notify(row, "pending")
    return row


def scan_timeouts():
    now_str = database.utc_now()
    with SessionLocal() as db:
        rows = db.execute(
            select(ApprovalRequest)
            .where(
                ApprovalRequest.status == "pending",
                ApprovalRequest.timeout_at < now_str,
            )
        ).scalars().all()
        for row in rows:
            row.status = "timeout"
            row.decided_at = now_str
            row.decided_by = "system"
            row.reason = "Auto-timeout"
            audit.log_event(
                agent_id=row.agent_id,
                action="approval_timeout",
                resource=row.resource,
                decision="deny",
                reason="Approval request timed out (treated as denied)",
            )
        db.commit()
    if rows:
        logger.info("approval timeout: %d requests expired", len(rows))


def _ws_notify(row: ApprovalRequest, event: str):
    try:
        from app.ws import ws_manager
        ws_manager.emit_audit({
            "type": "approval_update",
            "event": event,
            "approval_id": row.id,
            "agent_id": row.agent_id,
            "action": row.action,
            "resource": row.resource,
            "risk_score": row.risk_score,
            "status": row.status,
        })
    except Exception as e:
        logger.debug("ws notify failed: %s", e)


def _send_feishu_card(row: ApprovalRequest):
    url = settings.FEISHU_WEBHOOK_URL
    if not url:
        return
    base_url = os.environ.get("APPROVAL_CALLBACK_BASE_URL", f"http://{settings.HOST}:{settings.PORT}")
    try:
        import httpx
        card = {
            "msg_type": "interactive",
            "card": {
                "header": {"title": {"tag": "plain_text", "content": "⚠️ Agent IAM 审批请求"}},
                "elements": [
                    {"tag": "div", "text": {"tag": "lark_md", "content": f"**Agent**: {row.agent_id}\n**Action**: {row.action}\n**Resource**: {row.resource}\n**Risk**: {row.risk_score:.2f}"}},
                    {"tag": "action", "actions": [
                        {"tag": "button", "text": {"tag": "plain_text", "content": "✅ Allow"}, "type": "primary", "url": f"{base_url}/api/feishu/approval-callback?approval_id={row.id}&decision=approved"},
                        {"tag": "button", "text": {"tag": "plain_text", "content": "❌ Deny"}, "type": "danger", "url": f"{base_url}/api/feishu/approval-callback?approval_id={row.id}&decision=denied"},
                    ]},
                ],
            },
        }
        httpx.post(url, json=card, timeout=5)
        logger.info("feishu card sent for approval %d", row.id)
    except Exception as e:
        logger.warning("feishu card failed: %s", e)
