"""
AgentPass SDK Adapter for Agent Identity System 1.3

This adapter provides a bridge between the existing auth/policy system
and the new AgentPass SDK. It maintains backward compatibility while
enabling future migration to full SDK usage.
"""
from __future__ import annotations

import sys
import csv
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from io import StringIO

# Add SDK to path if not already available
_sdk_path = Path(__file__).parent.parent / "agentpass-sdk" / "src"
if _sdk_path.exists() and str(_sdk_path) not in sys.path:
    sys.path.insert(0, str(_sdk_path))

from agentpass import Guard, Policy, PolicyRule, Priority, Audit, AuditEvent  # noqa: E402


class AuditAdapter:
    _instance: Optional["AuditAdapter"] = None
    _events: List[Dict[str, Any]] = []

    def __init__(self):
        self.sdk_audit = Audit(storage_backend=None)
        self._events = []

    @classmethod
    def get_instance(cls) -> "AuditAdapter":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def log_event(
        self,
        event_type: str,
        agent_id: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        status: str = "unknown",
        ip_address: str | None = None,
        token_id: str | None = None,
        context: Dict[str, Any] | None = None,
        **extra_fields
    ) -> None:
        event = AuditEvent(
            event_type=event_type,
            user_id=agent_id,
            resource=resource,
            action=action,
            status=status,
            ip_address=ip_address,
            details=context or {}
        )
        self.sdk_audit.log_event(event)

        event_dict = {
            "id": event.id,
            "event_type": event_type,
            "agent_id": agent_id,
            "resource": resource,
            "action": action,
            "status": status,
            "ip_address": ip_address,
            "token_id": token_id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else datetime.utcnow().isoformat(),
            "context": context or {},
            **extra_fields
        }
        self._events.append(event_dict)

    def get_events(
        self,
        filters: Dict[str, Any] | None = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        filtered = self._events
        if filters:
            if "agent_id" in filters or "user_id" in filters:
                uid = filters.get("agent_id") or filters.get("user_id")
                filtered = [e for e in filtered if e.get("agent_id") == uid]
            if "action" in filters:
                filtered = [e for e in filtered if e.get("action") == filters["action"]]
            if "status" in filters:
                filtered = [e for e in filtered if e.get("status") == filters["status"]]
        return filtered[-limit:]

    def get_all_events(self) -> List[Dict[str, Any]]:
        return self._events.copy()

    def export_to_json(self, file_path: str | None = None) -> str:
        json_str = json.dumps(self._events, indent=2, ensure_ascii=False)
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(json_str)
        return json_str

    def export_to_csv(self, file_path: str | None = None) -> str:
        if not self._events:
            return ""

        output = StringIO()
        fieldnames = ["id", "event_type", "agent_id", "resource", "action", "status", "ip_address", "token_id", "timestamp"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(self._events)
        csv_str = output.getvalue()

        if file_path:
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_str)
        return csv_str

    def clear_events(self) -> None:
        self._events.clear()

    def get_event_count(self) -> int:
        return len(self._events)


class AgentPassAdapter:
    _instance: Optional["AgentPassAdapter"] = None

    def __init__(self, secret: str):
        self.guard = Guard(secret=secret)
        self._setup_default_policies()

    def _setup_default_policies(self):
        """Setup default policies matching existing permission system"""
        self.guard.policies = {
            "rbac_policy": Policy(
                id="rbac_policy",
                name="RBAC Policy",
                priority_strategy=Priority.DENY_OVERRIDE,
                rules=[
                    PolicyRule(
                        resource="doc:*",
                        action="read_doc",
                        effect="allow",
                        priority=50,
                        conditions={"role": {"require": ["basic", "editor", "operator", "admin"]}},
                        description="All roles can read docs"
                    ),
                    PolicyRule(
                        resource="doc:*",
                        action="write_doc",
                        effect="allow",
                        priority=50,
                        conditions={"role": {"require": ["editor", "operator", "admin"]}},
                        description="Editor+ roles can write docs"
                    ),
                    PolicyRule(
                        resource="task:*",
                        action="execute_task",
                        effect="allow",
                        priority=50,
                        conditions={"role": {"require": ["operator", "admin"]}},
                        description="Operator+ roles can execute tasks"
                    ),
                    PolicyRule(
                        resource="api:*",
                        action="call_api",
                        effect="allow",
                        priority=50,
                        conditions={"role": {"require": ["operator", "admin"]}},
                        description="Operator+ roles can call APIs"
                    ),
                    PolicyRule(
                        resource="agent:*",
                        action="delegate_task",
                        effect="allow",
                        priority=50,
                        conditions={"role": {"require": ["operator", "admin"]}},
                        description="Operator+ roles can delegate tasks"
                    ),
                    PolicyRule(
                        resource="admin:*",
                        action="*",
                        effect="allow",
                        priority=80,
                        conditions={"role": {"require": ["admin"]}},
                        description="Admin has access to admin resources"
                    ),
                    PolicyRule(
                        resource="*",
                        action="*",
                        effect="deny",
                        priority=0,
                        description="Default deny"
                    ),
                ]
            )
        }

    @classmethod
    def get_instance(cls, secret: str) -> "AgentPassAdapter":
        if cls._instance is None:
            cls._instance = cls(secret)
        return cls._instance

    def create_token(self, agent_id: str, role: str = "user", **extra_claims) -> str:
        return self.guard.issue_token(agent_id, role=role, **extra_claims)

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        return self.guard.authenticate(token)

    def check_permission(
        self,
        token: str,
        resource: str,
        action: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return self.guard.check(token=token, action=action, resource=resource)

    def check_permission_by_agent(
        self,
        agent_id: str,
        role: str,
        resource: str,
        action: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Check permission using agent info directly (without token)"""
        token = self.guard.issue_token(agent_id, role=role)
        return self.guard.check(token=token, action=action, resource=resource)


def get_adapter(secret: str) -> AgentPassAdapter:
    return AgentPassAdapter.get_instance(secret)


def get_audit_adapter() -> AuditAdapter:
    return AuditAdapter.get_instance()
