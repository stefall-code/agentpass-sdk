from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app import audit, auth, database, identity, permission, policy, schemas
from app.dependencies import require_auth

resource_router = APIRouter(tags=["Resources"])


@resource_router.get("/resource/docs/{doc_id}", response_model=schemas.DocumentResponse)
def read_document(doc_id: str, context: auth.AuthContext = Depends(require_auth)) -> schemas.DocumentResponse:
    document = database.get_document(doc_id)
    if not document:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")

    decision = policy.evaluate(
        agent=context.agent,
        action="read_doc",
        resource=f"doc:{doc_id}",
        resource_meta={"sensitivity": document["sensitivity"]},
    )
    audit.log_event(
        agent_id=context.agent["agent_id"],
        action="read_doc",
        resource=f"doc:{doc_id}",
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        ip_address=context.request_ip,
        token_id=context.token_id,
        context={"doc_id": doc_id},
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)
    return schemas.DocumentResponse(**document)


@resource_router.put("/resource/docs/{doc_id}", response_model=schemas.DocumentResponse)
def write_document(
    doc_id: str,
    payload: schemas.DocumentWriteRequest,
    context: auth.AuthContext = Depends(require_auth),
) -> schemas.DocumentResponse:
    try:
        permission.validate_sensitivity(payload.sensitivity)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    existing = database.get_document(doc_id)
    target_sensitivity = existing["sensitivity"] if existing else payload.sensitivity

    decision = policy.evaluate(
        agent=context.agent,
        action="write_doc",
        resource=f"doc:{doc_id}",
        resource_meta={"sensitivity": target_sensitivity},
    )
    audit.log_event(
        agent_id=context.agent["agent_id"],
        action="write_doc",
        resource=f"doc:{doc_id}",
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        ip_address=context.request_ip,
        token_id=context.token_id,
        context={"doc_id": doc_id, "existing": bool(existing)},
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    final_sensitivity = target_sensitivity
    if context.agent["role"] == "admin":
        final_sensitivity = payload.sensitivity

    saved = database.upsert_document(
        doc_id=doc_id,
        content=payload.content,
        sensitivity=final_sensitivity,
        updated_by=context.agent["agent_id"],
    )
    return schemas.DocumentResponse(**saved)


@resource_router.post("/tasks/execute", response_model=schemas.TaskExecutionResponse)
def execute_task(
    payload: schemas.TaskExecutionRequest,
    context: auth.AuthContext = Depends(require_auth),
) -> schemas.TaskExecutionResponse:
    decision = policy.evaluate(
        agent=context.agent,
        action="execute_task",
        resource=f"task:{payload.resource}",
        resource_meta={"sensitivity": "internal"},
    )
    audit.log_event(
        agent_id=context.agent["agent_id"],
        action="execute_task",
        resource=f"task:{payload.resource}",
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        ip_address=context.request_ip,
        token_id=context.token_id,
        context={"task_name": payload.task_name},
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    execution_id = identity.generate_execution_id()
    return schemas.TaskExecutionResponse(
        execution_id=execution_id,
        status="accepted",
        task_name=payload.task_name,
        resource=payload.resource,
        result_preview=(
            f"Task '{payload.task_name}' accepted for secure execution on '{payload.resource}' "
            f"by agent '{context.agent['agent_id']}'."
        ),
    )


@resource_router.post("/integrations/call", response_model=schemas.IntegrationCallResponse)
def call_integration(
    payload: schemas.IntegrationCallRequest,
    context: auth.AuthContext = Depends(require_auth),
) -> schemas.IntegrationCallResponse:
    decision = policy.evaluate(
        agent=context.agent,
        action="call_api",
        resource=f"api:{payload.service_name}",
        resource_meta={"sensitivity": "internal"},
    )
    audit.log_event(
        agent_id=context.agent["agent_id"],
        action="call_api",
        resource=f"api:{payload.service_name}",
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        ip_address=context.request_ip,
        token_id=context.token_id,
        context={"service_name": payload.service_name},
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    return schemas.IntegrationCallResponse(
        service_name=payload.service_name,
        status="ok",
        echoed_payload=payload.payload,
        message=f"Simulated upstream call to '{payload.service_name}' completed.",
    )
