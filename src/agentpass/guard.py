from pydantic import BaseModel, Field, PrivateAttr, ConfigDict
from typing import Dict, Any, Optional, List
from .auth import Auth
from .policy import Policy, PolicyRule
from .risk import Risk, RiskLevel, AnomalyDetector, FraudDetector
from .audit import Audit, AuditEvent
from .prompt_defense import PromptDefense, PromptInjectionResult


class Guard(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    secret: str
    auth: Auth = Field(default=None)
    policies: Dict[str, Policy] = Field(default_factory=dict)
    risk: Risk = Field(default=None)
    audit: Audit = Field(default=None)
    prompt_defense: PromptDefense = Field(default=None)
    _is_initialized: bool = PrivateAttr(default=False)

    def __init__(self, **data):
        super().__init__(**data)
        if not self._is_initialized:
            self._setup_default_components()

    def _setup_default_components(self):
        self.auth = Auth(secret_key=self.secret)

        self.audit = Audit(storage_backend=None)

        detectors = [
            AnomalyDetector(name="anomaly_detector", version="1.0"),
            FraudDetector(name="fraud_detector", version="1.0")
        ]
        self.risk = Risk(detectors=detectors)
        
        self.prompt_defense = PromptDefense()

        self.policies = {
            "default": Policy(
                id="default",
                name="Default Policy",
                rules=[
                    PolicyRule(resource="*", action="read_doc", effect="allow", priority=50),
                    PolicyRule(resource="*", action="write_doc", effect="allow", priority=50),
                    PolicyRule(resource="admin_panel", action="*", effect="deny", priority=100),
                    PolicyRule(resource="*", action="*", effect="deny", priority=0),
                ]
            )
        }
        self._is_initialized = True

    def issue_token(self, agent_id: str, role: str = "user", **extra_claims) -> str:
        payload = {
            "sub": agent_id,
            "role": role,
            **extra_claims
        }
        token = self.auth.create_access_token(payload)

        self._log_audit_event(
            event_type="token_issued",
            user_id=agent_id,
            action="issue_token",
            status="success",
            details={"role": role}
        )

        return token

    def check(self, token: str, action: str, resource: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        payload = self.auth.verify_token(token)

        if not payload:
            self._log_audit_event(
                event_type="access_check",
                action=action,
                resource=resource,
                status="deny",
                details={"reason": "invalid_token"}
            )
            return {
                "allowed": False,
                "reason": "Invalid or expired token",
                "risk_level": "unknown"
            }

        agent_id = payload.get("sub", "unknown")
        role = payload.get("role", "user")
        context = context or {}

        # Prompt Injection Defense
        prompt_injection_result = None
        if "prompt" in context:
            prompt_injection_result = self.prompt_defense.analyze(context["prompt"])
            if not prompt_injection_result.is_safe:
                self._log_audit_event(
                    event_type="prompt_injection_detected",
                    user_id=agent_id,
                    resource=resource,
                    action=action,
                    status="block",
                    details={
                        "risk_score": prompt_injection_result.risk_score,
                        "reason": prompt_injection_result.reason
                    }
                )
                return {
                    "allowed": False,
                    "reason": prompt_injection_result.reason,
                    "risk_level": "critical" if prompt_injection_result.risk_score > 0.7 else "high",
                    "risk_score": prompt_injection_result.risk_score,
                    "agent_id": agent_id,
                    "role": role,
                    "prompt_injection": prompt_injection_result.model_dump()
                }

        risk_context = {
            "user_id": agent_id,
            "resource": resource,
            "action": action,
            "role": role
        }
        risk_assessment = self.risk.assess_risk(risk_context)

        authorized = self._check_authorization(role, resource, action)

        if risk_assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            decision = "block"
            allowed = False
            reason = f"High risk detected: {risk_assessment.risk_level.value}"
        elif not authorized:
            decision = "deny"
            allowed = False
            reason = f"Role '{role}' is not authorized for {action} on {resource}"
        else:
            decision = "allow"
            allowed = True
            reason = "Access granted"

        self._log_audit_event(
            event_type="access_check",
            user_id=agent_id,
            resource=resource,
            action=action,
            status=decision,
            details={
                "role": role,
                "risk_level": risk_assessment.risk_level.value,
                "risk_score": risk_assessment.risk_score
            }
        )

        return {
            "allowed": allowed,
            "reason": reason,
            "risk_level": risk_assessment.risk_level.value,
            "risk_score": risk_assessment.risk_score,
            "agent_id": agent_id,
            "role": role
        }

    def _check_authorization(self, role: str, resource: str, action: str) -> bool:
        for policy in self.policies.values():
            if policy.evaluate(resource, action, {"role": role}):
                return True
        return False

    def add_policy(self, policy: Policy) -> None:
        self.policies[policy.id] = policy

    def authenticate(self, token: str) -> Optional[Dict[str, Any]]:
        return self.auth.verify_token(token)

    def authorize(self, user_id: str, resource: str, action: str) -> bool:
        return self._check_authorization(user_id, resource, action)

    def assess_and_protect(self, user_id: str, resource: str, action: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        context = context or {}
        context["user_id"] = user_id
        context["resource"] = resource
        context["action"] = action

        risk_assessment = self.risk.assess_risk(context)
        authorized = self._check_authorization(user_id, resource, action)

        if risk_assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            decision = "block"
            reason = f"High risk detected: {risk_assessment.risk_level.value}"
        elif not authorized:
            decision = "deny"
            reason = "Access not authorized"
        else:
            decision = "allow"
            reason = "Access granted"

        self._log_audit_event(
            event_type="access_control",
            user_id=user_id,
            resource=resource,
            action=action,
            status=decision,
            details={
                "risk_level": risk_assessment.risk_level.value,
                "risk_score": risk_assessment.risk_score,
                "recommendations": risk_assessment.recommendations
            }
        )

        return {
            "decision": decision,
            "reason": reason,
            "risk_assessment": risk_assessment.model_dump(),
            "authorized": authorized
        }

    def _log_audit_event(self, **kwargs):
        event = AuditEvent(**kwargs)
        self.audit.log_event(event)

    def analyze_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze a prompt for injection attacks directly.

        Args:
            prompt: The prompt text to analyze

        Returns:
            Dictionary with analysis results
        """
        result = self.prompt_defense.analyze(prompt)
        return result.model_dump()

    def check_with_context(self, agent_id: str, action: str, resource: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Check authorization with context without token validation.
        Used for internal service-to-service calls like OpenClaw.

        Args:
            agent_id: The agent identifier
            action: The action to perform
            resource: The resource to access
            context: Additional context including role, user, etc.

        Returns:
            Dictionary with allowed, reason, risk_score, etc.
        """
        context = context or {}
        role = context.get("role", "user")
        user = context.get("user", agent_id)

        # Prompt Injection Defense
        prompt_risk_score = context.get("prompt_risk_score", 0.0)
        if prompt_risk_score > 0.0:
            risk_assessment = self.risk.assess_risk({
                "user_id": agent_id,
                "resource": resource,
                "action": action,
                "role": role,
                "prompt_risk_score": prompt_risk_score
            })
        else:
            risk_assessment = self.risk.assess_risk({
                "user_id": agent_id,
                "resource": resource,
                "action": action,
                "role": role
            })

        authorized = self._check_authorization(role, resource, action)

        if risk_assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            decision = "block"
            allowed = False
            reason = f"High risk detected: {risk_assessment.risk_level.value}"
        elif not authorized:
            decision = "deny"
            allowed = False
            reason = f"Role '{role}' is not authorized for {action} on {resource}"
        else:
            decision = "allow"
            allowed = True
            reason = "Access granted"

        self._log_audit_event(
            event_type="openclaw_check",
            user_id=agent_id,
            resource=resource,
            action=action,
            status=decision,
            details={
                "user": user,
                "role": role,
                "risk_level": risk_assessment.risk_level.value,
                "risk_score": risk_assessment.risk_score,
                "source": "openclaw"
            }
        )

        return {
            "allowed": allowed,
            "reason": reason,
            "risk_level": risk_assessment.risk_level.value,
            "risk_score": risk_assessment.risk_score,
            "agent_id": agent_id,
            "role": role,
            "user": user
        }
