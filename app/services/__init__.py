from app.services.agent_service import AgentService
from app.services.audit_service import AuditService
from app.services.resource_service import ResourceService
from app.services.background import start_background_tasks, stop_background_tasks

agent_service = AgentService()
audit_service = AuditService()
resource_service = ResourceService()

__all__ = ["agent_service", "audit_service", "resource_service", "start_background_tasks", "stop_background_tasks"]
