from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth import AuthContext, get_auth_context

logger = logging.getLogger("agent_system")
drift_router = APIRouter(prefix="/api/drift", tags=["Drift Detection"])


class ConversationMessage(BaseModel):
    role: str
    content: str


class DriftAnalyzeRequest(BaseModel):
    agent_id: str
    conversation: List[ConversationMessage]


class DriftAnalyzeResponse(BaseModel):
    drift_detected: bool
    drift_score: float
    injection_turn_index: Optional[int] = None
    distance_series: List[float]


@drift_router.post("/analyze", response_model=DriftAnalyzeResponse)
def analyze_drift(
    payload: DriftAnalyzeRequest,
    context: AuthContext = Depends(get_auth_context),
) -> DriftAnalyzeResponse:
    from app.services.drift_detector import DriftDetector
    detector = DriftDetector()
    texts = [m.content for m in payload.conversation if m.role == "assistant"]
    if len(texts) < 2:
        return DriftAnalyzeResponse(drift_detected=False, drift_score=0.0, distance_series=[])

    result = detector.analyze(texts, agent_id=payload.agent_id)
    return DriftAnalyzeResponse(**result)
