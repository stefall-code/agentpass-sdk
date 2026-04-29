from __future__ import annotations

import logging
from typing import Dict, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.auth import AuthContext, get_auth_context

logger = logging.getLogger("agent_system")
context_router = APIRouter(prefix="/api/context", tags=["Context Isolation"])


class SealRequest(BaseModel):
    agent_id: str
    data: Dict[str, Any]
    fields: list[str] = Field(default_factory=list)


class UnsealRequest(BaseModel):
    agent_id: str
    sealed_blob: str


class SealResponse(BaseModel):
    sealed_blob: str
    fields_sealed: list[str]
    fields_filtered: list[str]


class UnsealResponse(BaseModel):
    data: Dict[str, Any]
    success: bool
    violation: bool = False


@context_router.post("/seal", response_model=SealResponse)
def seal_context(
    payload: SealRequest,
    context: AuthContext = Depends(get_auth_context),
) -> SealResponse:
    from app.services.context_guard import ContextGuard
    guard = ContextGuard()
    result = guard.seal(payload.agent_id, payload.data, payload.fields)
    return SealResponse(**result)


@context_router.post("/unseal", response_model=UnsealResponse)
def unseal_context(
    payload: UnsealRequest,
    context: AuthContext = Depends(get_auth_context),
) -> UnsealResponse:
    from app.services.context_guard import ContextGuard
    guard = ContextGuard()
    result = guard.unseal(payload.agent_id, payload.sealed_blob)
    return UnsealResponse(**result)
