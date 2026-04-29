# DEPRECATED: This file references old model names and is not imported anywhere.
# Use app/database.py and app/identity.py for data operations.
from __future__ import annotations

import json
import datetime

from sqlalchemy import select, delete, func, desc
from sqlalchemy.orm import Session

from app.models import Agent, Document, AuditLog, Token
from app.config import settings


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class AgentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get(self, agent_id: str) -> dict | None:
        row = self.db.get(Agent, agent_id)
        return row.to_dict() if row else None

    def list_all(self) -> list[dict]:
        rows = self.db.execute(select(Agent)).scalars().all()
        return [r.to_dict() for r in rows]

    def upsert(self, agent_id: str, name: str, role: str, api_key: str,
               attributes: dict | None = None, status: str = "active",
               status_reason: str | None = None, usage_count: int = 0) -> dict:
        existing = self.db.get(Agent, agent_id)
        now = _now()
        if existing:
            existing.name = name
            existing.role = role
            existing.api_key = api_key
            existing.attributes = json.dumps(attributes or {})
            existing.updated_at = now
            self.db.commit()
            self.db.refresh(existing)
            return existing.to_dict()
        row = Agent(
            agent_id=agent_id, name=name, role=role, api_key=api_key,
            attributes=json.dumps(attributes or {}), status=status,
            status_reason=status_reason, usage_count=usage_count,
            created_at=now, updated_at=now,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row.to_dict()

    def update_fields(self, agent_id: str, **fields) -> dict | None:
        row = self.db.get(Agent, agent_id)
        if not row:
            return None
        for k, v in fields.items():
            if v is not None:
                if k == "attributes":
                    setattr(row, k, json.dumps(v))
                else:
                    setattr(row, k, v)
        row.updated_at = _now()
        self.db.commit()
        self.db.refresh(row)
        return row.to_dict()

    def update_status(self, agent_id: str, status: str, reason: str | None) -> dict | None:
        row = self.db.get(Agent, agent_id)
        if not row:
            return None
        row.status = status
        row.status_reason = reason
        row.updated_at = _now()
        self.db.commit()
        self.db.refresh(row)
        return row.to_dict()

    def increment_usage(self, agent_id: str) -> None:
        row = self.db.get(Agent, agent_id)
        if row:
            row.usage_count += 1
            row.updated_at = _now()
            self.db.commit()

    def remove(self, agent_id: str) -> bool:
        row = self.db.get(Agent, agent_id)
        if not row:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

    def find_by_api_key(self, api_key: str) -> dict | None:
        row = self.db.execute(select(Agent).where(Agent.api_key == api_key)).scalar_one_or_none()
        return row.to_dict() if row else None


class DocumentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get(self, doc_id: str) -> dict | None:
        row = self.db.get(Document, doc_id)
        return row.to_dict() if row else None

    def list_all(self) -> list[dict]:
        rows = self.db.execute(select(Document)).scalars().all()
        return [r.to_dict() for r in rows]

    def upsert(self, doc_id: str, content: str, sensitivity: str,
               updated_by: str | None = None) -> dict:
        existing = self.db.get(Document, doc_id)
        now = _now()
        if existing:
            existing.content = content
            existing.sensitivity = sensitivity
            existing.updated_by = updated_by
            existing.updated_at = now
            self.db.commit()
            self.db.refresh(existing)
            return existing.to_dict()
        row = Document(
            doc_id=doc_id, content=content, sensitivity=sensitivity,
            updated_by=updated_by, created_at=now, updated_at=now,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row.to_dict()

    def reset_defaults(self) -> list[dict]:
        self.db.execute(delete(Document))
        self.db.commit()
        results = []
        for doc in settings.DEFAULT_DOCS:
            results.append(self.upsert(
                doc_id=doc["doc_id"],
                content=doc["content"],
                sensitivity=doc["sensitivity"],
            ))
        return results


class AuditRepository:
    def __init__(self, db: Session):
        self.db = db

    def insert(self, agent_id: str, action: str, resource: str,
               decision: str, reason: str, ip_address: str | None = None,
               token_id: str | None = None, context: dict | None = None) -> dict:
        row = AuditLog(
            agent_id=agent_id, action=action, resource=resource,
            decision=decision, reason=reason, ip_address=ip_address,
            token_id=token_id, context=json.dumps(context or {}),
            timestamp=_now(),
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row.to_dict()

    def fetch_recent(self, limit: int = 20, agent_id: str | None = None,
                     decision: str | None = None, action: str | None = None) -> list[dict]:
        q = select(AuditLog).order_by(desc(AuditLog.id))
        if agent_id:
            q = q.where(AuditLog.agent_id == agent_id)
        if decision:
            q = q.where(AuditLog.decision == decision)
        if action:
            q = q.where(AuditLog.action == action)
        rows = self.db.execute(q.limit(limit)).scalars().all()
        return [r.to_dict() for r in rows]

    def count_by_decision(self) -> dict:
        allows = self.db.execute(
            select(func.count()).where(AuditLog.decision == "allow")
        ).scalar() or 0
        denies = self.db.execute(
            select(func.count()).where(AuditLog.decision == "deny")
        ).scalar() or 0
        return {"allow": allows, "deny": denies}

    def total_count(self) -> int:
        return self.db.execute(select(func.count()).select_from(AuditLog)).scalar() or 0

    def clear(self) -> int:
        count = self.total_count()
        self.db.execute(delete(AuditLog))
        self.db.commit()
        return count


class TokenRepository:
    def __init__(self, db: Session):
        self.db = db

    def get(self, token_id: str) -> dict | None:
        row = self.db.get(Token, token_id)
        return row.to_dict() if row else None

    def create(self, token_id: str, agent_id: str, ip_address: str | None = None) -> dict:
        row = Token(
            token_id=token_id, agent_id=agent_id,
            ip_address=ip_address, usage_count=0, created_at=_now(),
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row.to_dict()

    def increment_usage(self, token_id: str) -> None:
        row = self.db.get(Token, token_id)
        if row:
            row.usage_count += 1
            self.db.commit()

    def clear_all(self) -> int:
        count = self.db.execute(select(func.count()).select_from(Token)).scalar() or 0
        self.db.execute(delete(Token))
        self.db.commit()
        return count
