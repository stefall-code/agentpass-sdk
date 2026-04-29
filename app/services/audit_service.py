from __future__ import annotations

from app import audit, database, identity
from app.config import settings


class AuditService:
    def reset_demo(self, caller_agent_id: str, caller_ip: str, token_id: str | None) -> dict:
        cleared_tokens = database.clear_tokens()
        cleared_logs = audit.clear_logs()
        documents = database.reset_documents()
        identity.sync_demo_agents(reset_state=True)
        audit.log_event(
            agent_id=caller_agent_id,
            action="reset_demo_state",
            resource="admin:demo_reset",
            decision="allow",
            reason="Demo state reset by administrator.",
            ip_address=caller_ip,
            token_id=token_id,
            context={"cleared_tokens": cleared_tokens, "cleared_logs": cleared_logs},
        )
        return {
            "cleared_tokens": cleared_tokens,
            "cleared_logs": cleared_logs,
            "documents_restored": len(documents),
        }

    def get_dashboard_data(self) -> dict:
        snapshot = database.get_system_snapshot()
        return {
            "snapshot": snapshot,
            "audit": audit.get_audit_summary(),
            "demo_agents": [
                {"agent_id": item["agent_id"], "name": item["name"], "role": item["role"]}
                for item in settings.DEMO_AGENTS
            ],
        }
