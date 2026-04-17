from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, Optional, List
from enum import Enum
from .detector import Detector, AnomalyDetector, FraudDetector, DetectionResult

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RiskAssessment(BaseModel):
    risk_level: RiskLevel
    risk_score: float = Field(..., ge=0.0, le=1.0)
    factors: List[Dict[str, Any]] = []
    recommendations: List[str] = []

class Risk(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    detectors: List[Any] = []

    def assess_risk(self, context: Dict[str, Any]) -> RiskAssessment:
        risk_score = 0.0
        factors = []
        recommendations = []

        for detector in self.detectors:
            result = detector.detect(context)
            if result.is_detected:
                risk_score += result.risk_score
                factors.append({
                    "detector": detector.name,
                    "score": result.risk_score,
                    "details": result.details
                })

        risk_score = min(1.0, risk_score)

        if risk_score >= 0.8:
            risk_level = RiskLevel.CRITICAL
            recommendations.append("Block access immediately")
            recommendations.append("Review account activity")
        elif risk_score >= 0.6:
            risk_level = RiskLevel.HIGH
            recommendations.append("Require additional verification")
            recommendations.append("Monitor activity closely")
        elif risk_score >= 0.4:
            risk_level = RiskLevel.MEDIUM
            recommendations.append("Send security alert")
        else:
            risk_level = RiskLevel.LOW

        return RiskAssessment(
            risk_level=risk_level,
            risk_score=risk_score,
            factors=factors,
            recommendations=recommendations
        )
