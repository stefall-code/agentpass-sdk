from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.config import settings
from app import audit, auth, identity, permission, schemas

auth_router = APIRouter(tags=["Authentication"])


@auth_router.get("/me", response_model=schemas.AgentProfileResponse)
def get_current_agent(context: auth.AuthContext = Depends(auth.get_auth_context)) -> schemas.AgentProfileResponse:
    agent = context.agent
    return schemas.AgentProfileResponse(
        agent_id=agent["agent_id"],
        name=agent["name"],
        role=agent["role"],
        status=agent["status"],
        permissions=permission.list_permissions(agent["role"]),
        metadata=agent.get("metadata", {}),
        attributes=agent.get("attributes", {}),
        created_at=agent["created_at"],
        last_login_at=agent.get("last_login_at"),
    )


@auth_router.post("/register", response_model=schemas.RegisterAgentResponse, status_code=status.HTTP_201_CREATED)
def register_agent(payload: schemas.RegisterAgentRequest) -> schemas.RegisterAgentResponse:
    agent = identity.create_agent(
        name=payload.name,
        role=payload.role,
        metadata=payload.metadata,
        attributes=payload.attributes,
    )
    audit.log_event(
        agent_id=agent["agent_id"],
        action="register",
        resource=f"agent:{agent['agent_id']}",
        decision="allow",
        reason="Agent self-registered.",
        ip_address="self-register",
    )
    return schemas.RegisterAgentResponse(
        message="Agent registered successfully.",
        agent_id=agent["agent_id"],
        name=agent["name"],
        role=agent["role"],
        api_key=agent["api_key"],
    )


@auth_router.post("/login", response_model=schemas.TokenResponse)
def login(payload: schemas.LoginRequest, request: Request) -> schemas.TokenResponse:
    agent = identity.authenticate_agent(payload.agent_id, payload.api_key)
    if not agent:
        raise auth._exc(401, "Invalid agent_id or api_key.")
    if agent["status"] != "active":
        raise auth._exc(403, f"Agent status is {agent['status']}. Contact an administrator.")

    token_info = auth.issue_token(
        agent_id=agent["agent_id"],
        role=agent["role"],
        bound_ip=payload.bound_ip,
        usage_limit=payload.usage_limit,
        expires_in_minutes=payload.expires_in_minutes,
    )
    identity.record_login(agent["agent_id"])
    audit.log_event(
        agent_id=agent["agent_id"],
        action="login",
        resource="auth:login",
        decision="allow",
        reason="Token issued successfully.",
        ip_address=request.client.host if request.client else "unknown",
        token_id=token_info["jti"],
        context={"usage_limit": token_info["usage_limit"], "expires_at": token_info["expires_at"]},
    )
    return schemas.TokenResponse(**token_info)


@auth_router.post("/login/batch", response_model=List[schemas.BatchLoginItemResponse])
def batch_login(payload: schemas.BatchLoginRequest, request: Request) -> List[schemas.BatchLoginItemResponse]:
    admin = identity.authenticate_agent(payload.admin_agent_id, payload.admin_api_key)
    if not admin or admin["role"] != "admin":
        raise auth._exc(401, "Batch login requires admin credentials.")

    results = []
    for item in payload.agents:
        agent = identity.authenticate_agent(item.agent_id, item.api_key)
        if not agent:
            results.append(schemas.BatchLoginItemResponse(
                agent_id=item.agent_id, success=False, error="Invalid credentials.", token=None,
            ))
            continue
        if agent["status"] != "active":
            results.append(schemas.BatchLoginItemResponse(
                agent_id=item.agent_id, success=False, error=f"Agent status is {agent['status']}.", token=None,
            ))
            continue
        token_info = auth.issue_token(
            agent_id=agent["agent_id"],
            role=agent["role"],
            bound_ip=item.bound_ip,
            usage_limit=item.usage_limit,
            expires_in_minutes=item.expires_in_minutes,
        )
        identity.record_login(agent["agent_id"])
        audit.log_event(
            agent_id=agent["agent_id"],
            action="login",
            resource="auth:batch_login",
            decision="allow",
            reason="Token issued via batch login.",
            ip_address=request.client.host if request.client else "unknown",
            token_id=token_info["jti"],
        )
        results.append(schemas.BatchLoginItemResponse(
            agent_id=item.agent_id,
            success=True,
            error=None,
            token=schemas.TokenResponse(**token_info),
        ))
    return results


@auth_router.get("/auth/introspect", response_model=schemas.TokenIntrospectionResponse)
def introspect_current_token(request: Request) -> schemas.TokenIntrospectionResponse:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    token_value = auth_header[7:]
    try:
        payload = auth.decode_token(token_value)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token.")
    jti = payload.get("jti")
    agent_id = payload.get("sub")
    role = payload.get("role")
    if not jti:
        raise HTTPException(status_code=401, detail="Token missing jti.")
    token_state = auth.introspect_token(jti)
    if not token_state:
        raise HTTPException(status_code=404, detail="Token not found.")
    return schemas.TokenIntrospectionResponse(
        jti=token_state["jti"],
        agent_id=agent_id,
        role=role,
        active=bool(token_state["active"]),
        issued_at=token_state["issued_at"],
        expires_at=token_state["expires_at"],
        bound_ip=token_state["bound_ip"],
        usage_limit=token_state["usage_limit"],
        usage_count=token_state["usage_count"],
        usage_remaining=max(token_state["usage_limit"] - token_state["usage_count"], 0),
    )


@auth_router.post("/auth/revoke", response_model=schemas.ActionMessageResponse)
def revoke_current_token(context: auth.AuthContext = Depends(auth.get_auth_context)) -> schemas.ActionMessageResponse:
    revoked = auth.revoke_token(context.token_id)
    audit.log_event(
        agent_id=context.agent["agent_id"],
        action="revoke_token",
        resource="auth:revoke",
        decision="allow",
        reason="Current token revoked by agent.",
        ip_address=context.request_ip,
        token_id=context.token_id,
    )
    return schemas.ActionMessageResponse(
        message="Current token revoked." if revoked else "Token was already inactive.",
        details={"jti": context.token_id, "revoked": revoked},
    )


@auth_router.post("/auth/refresh", response_model=schemas.TokenResponse)
def refresh_token(payload: schemas.RefreshTokenRequest, request: Request) -> schemas.TokenResponse:
    """使用refresh_token换取新的access_token"""
    claims = auth.validate_refresh_token(payload.refresh_token)
    agent = identity.get_agent(claims["sub"])
    if not agent or agent["status"] != "active":
        raise auth._exc(401, "Agent not found or inactive.")

    old_jti = claims.get("jti")
    if old_jti:
        auth.revoke_token(old_jti)

    token_info = auth.issue_token(
        agent_id=agent["agent_id"],
        role=agent["role"],
        bound_ip=payload.bound_ip,
        usage_limit=payload.usage_limit or settings.DEFAULT_USAGE_LIMIT,
        expires_in_minutes=payload.expires_in_minutes or settings.TOKEN_EXPIRE_MINUTES,
    )
    audit.log_event(
        agent_id=agent["agent_id"],
        action="refresh_token",
        resource="auth:refresh",
        decision="allow",
        reason="Token refreshed successfully.",
        ip_address=request.client.host if request.client else "unknown",
        token_id=token_info["jti"],
        context={"old_jti": old_jti},
    )
    return schemas.TokenResponse(**token_info)
