from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status

from app import audit, policy
from app.auth import AuthContext, get_auth_context
from app.adapters import get_adapter
from app.config import settings

_agentpass = get_adapter(settings.JWT_SECRET)


def require_auth(
    context: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    return context


def require_permission(action: str, resource: str, resource_meta: dict | None = None):
    def _dependency(context: AuthContext = Depends(get_auth_context)) -> AuthContext:
        original_decision = policy.evaluate(
            agent=context.agent,
            action=action,
            resource=resource,
            resource_meta=resource_meta,
        )

        sdk_result = _agentpass.check_permission_by_agent(
            agent_id=context.agent["agent_id"],
            role=context.agent["role"],
            resource=resource,
            action=action,
            context={"role": context.agent["role"], "ip_address": context.request_ip}
        )

        # HitL: 高风险操作需要人工审批
        risk_score = 0.0
        if hasattr(original_decision, 'risk_score'):
            risk_score = original_decision.risk_score or 0.0
        elif isinstance(sdk_result, dict):
            risk_score = sdk_result.get("risk_score", 0.0)

        from app.services.reputation_service import ReputationEngine
        rep_engine = ReputationEngine()
        threshold = settings.HITL_RISK_THRESHOLD
        if rep_engine.should_lower_hitl_threshold(context.agent["agent_id"]):
            threshold = 0.3

        needs_approval = (
            risk_score > threshold
            or action in settings.HITL_CRITICAL_ACTIONS
        )

        if needs_approval and original_decision.allowed:
            from app.routers.approval import create_approval_request
            approval = create_approval_request(
                agent_id=context.agent["agent_id"],
                action=action,
                resource=resource,
                risk_score=risk_score,
                payload={"ip": context.request_ip, "token_id": context.token_id},
            )
            audit.log_event(
                agent_id=context.agent["agent_id"],
                action=action,
                resource=resource,
                decision="pending_approval",
                reason=f"HitL: risk_score={risk_score:.2f} > threshold={threshold:.2f}",
                ip_address=context.request_ip,
                token_id=context.token_id,
                context={"approval_id": approval.id, "status": "pending"},
            )
            raise HTTPException(
                status_code=202,
                detail={
                    "approval_id": approval.id,
                    "status": "pending",
                    "message": "Action requires human approval",
                    "risk_score": risk_score,
                },
            )

        audit.log_event(
            agent_id=context.agent["agent_id"],
            action=action,
            resource=resource,
            decision="allow" if original_decision.allowed else "deny",
            reason=original_decision.reason,
            ip_address=context.request_ip,
            token_id=context.token_id,
        )

        if not original_decision.allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=original_decision.reason)
        return context
    return _dependency


def require_admin_permission(action: str, resource: str, extra_context: dict | None = None):
    def _dependency(context: AuthContext = Depends(get_auth_context)) -> AuthContext:
        original_decision = policy.evaluate(
            agent=context.agent,
            action=action,
            resource=resource,
            resource_meta={"sensitivity": "confidential"},
        )

        audit.log_event(
            agent_id=context.agent["agent_id"],
            action=action,
            resource=resource,
            decision="allow" if original_decision.allowed else "deny",
            reason=original_decision.reason,
            ip_address=context.request_ip,
            token_id=context.token_id,
            context=extra_context or {},
        )

        if not original_decision.allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=original_decision.reason)
        return context
    return _dependency


def check_permission(action: str, resource_template: str, resource_meta: dict | None = None):
    def _dependency(request: Request, context: AuthContext = Depends(get_auth_context)) -> AuthContext:
        resource = resource_template
        for key, value in request.path_params.items():
            resource = resource.replace(f"{{{key}}}", str(value))

        original_decision = policy.evaluate(
            agent=context.agent,
            action=action,
            resource=resource,
            resource_meta=resource_meta,
        )

        audit.log_event(
            agent_id=context.agent["agent_id"],
            action=action,
            resource=resource,
            decision="allow" if original_decision.allowed else "deny",
            reason=original_decision.reason,
            ip_address=context.request_ip,
            token_id=context.token_id,
        )

        if not original_decision.allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=original_decision.reason)
        return context
    return _dependency


def _check_with_guard(
    context: AuthContext,
    action: str,
    resource: str,
    resource_meta: dict | None = None,
) -> dict:
    sdk_result = _agentpass.check_permission_by_agent(
        agent_id=context.agent["agent_id"],
        role=context.agent["role"],
        resource=resource,
        action=action,
        context={"role": context.agent["role"], "ip_address": context.request_ip}
    )
    return sdk_result
