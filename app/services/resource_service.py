from __future__ import annotations

from app import audit, database, permission, policy


class ResourceService:
    def read_document_with_audit(
        self,
        doc_id: str,
        agent: dict,
        caller_ip: str,
        token_id: str | None,
    ) -> dict:
        document = database.get_document(doc_id)
        if not document:
            return {"found": False, "allowed": False, "reason": "Document not found.", "document": None}

        decision = policy.evaluate(
            agent=agent,
            action="read_doc",
            resource=f"doc:{doc_id}",
            resource_meta={"sensitivity": document["sensitivity"]},
        )
        audit.log_event(
            agent_id=agent["agent_id"],
            action="read_doc",
            resource=f"doc:{doc_id}",
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            ip_address=caller_ip,
            token_id=token_id,
            context={"doc_id": doc_id},
        )
        return {"found": True, "allowed": decision.allowed, "reason": decision.reason, "document": document}

    def write_document_with_audit(
        self,
        doc_id: str,
        content: str,
        sensitivity: str,
        agent: dict,
        caller_ip: str,
        token_id: str | None,
    ) -> dict:
        try:
            permission.validate_sensitivity(sensitivity)
        except ValueError as exc:
            return {"allowed": False, "reason": str(exc), "document": None}

        existing = database.get_document(doc_id)
        target_sensitivity = existing["sensitivity"] if existing else sensitivity

        decision = policy.evaluate(
            agent=agent,
            action="write_doc",
            resource=f"doc:{doc_id}",
            resource_meta={"sensitivity": target_sensitivity},
        )
        audit.log_event(
            agent_id=agent["agent_id"],
            action="write_doc",
            resource=f"doc:{doc_id}",
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            ip_address=caller_ip,
            token_id=token_id,
            context={"doc_id": doc_id, "existing": bool(existing)},
        )
        if not decision.allowed:
            return {"allowed": False, "reason": decision.reason, "document": None}

        final_sensitivity = target_sensitivity
        if agent["role"] == "admin":
            final_sensitivity = sensitivity

        saved = database.upsert_document(
            doc_id=doc_id,
            content=content,
            sensitivity=final_sensitivity,
            updated_by=agent["agent_id"],
        )
        return {"allowed": True, "reason": "Document written.", "document": saved}

    def execute_task_with_audit(
        self,
        task_name: str,
        resource: str,
        agent: dict,
        caller_ip: str,
        token_id: str | None,
    ) -> dict:
        decision = policy.evaluate(
            agent=agent,
            action="execute_task",
            resource=f"task:{resource}",
            resource_meta={"sensitivity": "internal"},
        )
        audit.log_event(
            agent_id=agent["agent_id"],
            action="execute_task",
            resource=f"task:{resource}",
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            ip_address=caller_ip,
            token_id=token_id,
            context={"task_name": task_name},
        )
        return {"allowed": decision.allowed, "reason": decision.reason}
