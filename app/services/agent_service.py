from __future__ import annotations

from app import audit, identity, policy


class AgentService:
    def create_agent_with_audit(
        self,
        agent_id: str,
        name: str,
        role: str,
        api_key: str,
        attributes: dict | None,
        caller_agent_id: str,
        caller_ip: str,
        token_id: str | None,
    ) -> dict:
        agent = identity.create_agent(
            agent_id=agent_id,
            name=name,
            role=role,
            api_key=api_key,
            attributes=attributes,
        )
        audit.log_event(
            agent_id=caller_agent_id,
            action="create_agent",
            resource=f"agent:{agent_id}",
            decision="allow",
            reason="Agent created successfully.",
            ip_address=caller_ip,
            token_id=token_id,
            context={"new_agent_id": agent_id, "new_agent_role": role},
        )
        return agent

    def delete_agent_with_audit(
        self,
        agent_id: str,
        caller_agent_id: str,
        caller_ip: str,
        token_id: str | None,
    ) -> bool:
        deleted = identity.delete_agent(agent_id)
        audit.log_event(
            agent_id=caller_agent_id,
            action="delete_agent",
            resource=f"agent:{agent_id}",
            decision="allow",
            reason=f"Agent {agent_id} deleted.",
            ip_address=caller_ip,
            token_id=token_id,
        )
        return deleted

    def update_agent_with_audit(
        self,
        agent_id: str,
        caller_agent_id: str,
        caller_ip: str,
        token_id: str | None,
        **fields,
    ) -> dict:
        updated = identity.update_agent(agent_id=agent_id, **fields)
        audit.log_event(
            agent_id=caller_agent_id,
            action="update_agent",
            resource=f"agent:{agent_id}",
            decision="allow",
            reason="Agent updated successfully.",
            ip_address=caller_ip,
            token_id=token_id,
            context={"updated_fields": list(fields.keys())},
        )
        return updated

    def check_interaction(
        self,
        source_agent: dict,
        target_agent_id: str,
        interaction_type: str,
        caller_ip: str,
        token_id: str | None,
    ) -> dict:
        target = identity.get_agent(target_agent_id)
        if not target:
            return {"allowed": False, "reason": "Target agent not found.", "target": None}

        decision = policy.evaluate(
            agent=source_agent,
            action="interact_agent",
            resource=f"agent:{target_agent_id}",
            resource_meta={"sensitivity": target.get("attributes", {}).get("sensitivity", "internal")},
        )
        audit.log_event(
            agent_id=source_agent["agent_id"],
            action="interact_agent",
            resource=f"agent:{target_agent_id}",
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            ip_address=caller_ip,
            token_id=token_id,
            context={"target_agent_id": target_agent_id, "interaction_type": interaction_type},
        )
        return {"allowed": decision.allowed, "reason": decision.reason, "target": target}
