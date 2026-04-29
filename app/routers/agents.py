from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app import audit, auth, database, identity, policy, schemas
from app.dependencies import require_auth, require_permission, check_permission

agent_router = APIRouter(tags=["Agents"])


class AccessRequest(BaseModel):
    action: str
    resource: str


class AccessResponse(BaseModel):
    decision: str
    reason: str
    rule_id: str = ""
    agent_id: str
    action: str
    resource: str


@agent_router.post("/agents/access", response_model=AccessResponse)
def access_resource(
    payload: AccessRequest,
    context: auth.AuthContext = Depends(require_auth),
) -> AccessResponse:
    resource_meta: dict = {"sensitivity": "internal"}
    if payload.resource.startswith("doc:"):
        doc_id = payload.resource[4:]
        doc = database.get_document(doc_id)
        if doc:
            resource_meta["sensitivity"] = doc["sensitivity"]
    decision = policy.evaluate(
        agent=context.agent,
        action=payload.action,
        resource=payload.resource,
        resource_meta=resource_meta,
    )
    decision_str = "allow" if decision.allowed else "deny"
    audit.log_event(
        agent_id=context.agent["agent_id"],
        action=payload.action,
        resource=payload.resource,
        decision=decision_str,
        reason=decision.reason,
        ip_address=context.request_ip,
        token_id=context.token_id,
    )
    return AccessResponse(
        decision=decision_str,
        reason=decision.reason,
        rule_id=decision.rule_id,
        agent_id=context.agent["agent_id"],
        action=payload.action,
        resource=payload.resource,
    )


@agent_router.get("/agents", response_model=list[schemas.AgentResponse])
def list_agents(context: auth.AuthContext = Depends(require_auth)) -> list[schemas.AgentResponse]:
    agents = identity.list_agents()
    return [schemas.AgentResponse(**a) for a in agents]


@agent_router.get("/agents/{agent_id}", response_model=schemas.AgentDetailResponse)
def get_agent(agent_id: str, context: auth.AuthContext = Depends(require_auth)) -> schemas.AgentDetailResponse:
    agent = identity.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found.")
    return schemas.AgentDetailResponse(**agent)


@agent_router.post("/agents", response_model=schemas.AgentDetailResponse, status_code=status.HTTP_201_CREATED)
def create_agent(
    payload: schemas.AgentCreateRequest,
    context: auth.AuthContext = Depends(require_permission("create_agent", "agent:*", {"sensitivity": "confidential"})),
) -> schemas.AgentDetailResponse:
    if identity.get_agent(payload.agent_id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Agent already exists.")

    agent = identity.create_agent(
        name=payload.name,
        role=payload.role,
        api_key=payload.api_key,
        attributes=payload.attributes,
        preset_agent_id=payload.agent_id,
        preset_api_key=payload.api_key,
    )
    return schemas.AgentDetailResponse(**agent)


@agent_router.put("/agents/{agent_id}", response_model=schemas.AgentUpdateResponse)
def update_agent(
    agent_id: str,
    payload: schemas.AgentUpdateRequest,
    context: auth.AuthContext = Depends(check_permission("update_agent", "agent:{agent_id}", {"sensitivity": "confidential"})),
) -> schemas.AgentUpdateResponse:
    existing = identity.get_agent(agent_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found.")

    updated = identity.update_agent(
        agent_id=agent_id,
        name=payload.name,
        attributes=payload.attributes,
    )
    return schemas.AgentUpdateResponse(**updated)


@agent_router.delete("/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_agent(
    agent_id: str,
    context: auth.AuthContext = Depends(check_permission("delete_agent", "agent:{agent_id}", {"sensitivity": "confidential"})),
) -> None:
    existing = identity.get_agent(agent_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found.")
    identity.delete_agent(agent_id)


@agent_router.post("/agents/{agent_id}/interact", response_model=schemas.InteractionResponse)
def interact_with_agent(
    agent_id: str,
    payload: schemas.InteractionRequest,
    context: auth.AuthContext = Depends(require_auth),
) -> schemas.InteractionResponse:
    target = identity.get_agent(agent_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target agent not found.")

    decision = policy.evaluate(
        agent=context.agent,
        action="interact_agent",
        resource=f"agent:{agent_id}",
        resource_meta={"sensitivity": target.get("attributes", {}).get("sensitivity", "internal")},
    )
    audit.log_event(
        agent_id=context.agent["agent_id"],
        action="interact_agent",
        resource=f"agent:{agent_id}",
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        ip_address=context.request_ip,
        token_id=context.token_id,
        context={"target_agent_id": agent_id},
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    return schemas.InteractionResponse(
        source_agent_id=context.agent["agent_id"],
        target_agent_id=agent_id,
        interaction_type=payload.interaction_type,
        status="completed",
        message=f"Interaction '{payload.interaction_type}' with agent '{agent_id}' completed successfully.",
    )


@agent_router.post("/agents/delegate", response_model=schemas.DelegationResponse)
def delegate_task(
    payload: schemas.DelegateTaskRequest,
    context: auth.AuthContext = Depends(require_auth),
) -> schemas.DelegationResponse:
    target = identity.get_agent(payload.target_agent_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target agent not found.")

    decision = policy.evaluate(
        agent=context.agent,
        action="delegate_task",
        resource=f"agent:{payload.target_agent_id}",
        resource_meta={"sensitivity": "internal"},
    )
    audit.log_event(
        agent_id=context.agent["agent_id"],
        action="delegate_task",
        resource=f"agent:{payload.target_agent_id}",
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        ip_address=context.request_ip,
        token_id=context.token_id,
        context={"target_agent_id": payload.target_agent_id, "task_name": payload.task_name},
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    delegation_id = identity.generate_execution_id("delegation")
    return schemas.DelegationResponse(
        delegation_id=delegation_id,
        source_agent_id=context.agent["agent_id"],
        target_agent_id=payload.target_agent_id,
        task_name=payload.task_name,
        status="delegated",
    )
