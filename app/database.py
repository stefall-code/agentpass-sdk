from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from sqlalchemy import select, delete, func, desc, text, and_

from app.config import settings
from app.db import SessionLocal, engine, Base
from app.models import AgentRow, IssuedTokenRow, DocumentRow


_local = threading.local()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        for doc in settings.DEFAULT_DOCS:
            existing = db.get(DocumentRow, doc["doc_id"])
            if not existing:
                db.add(DocumentRow(
                    doc_id=doc["doc_id"],
                    content=doc["content"],
                    sensitivity=doc["sensitivity"],
                    updated_by="system",
                    updated_at=utc_now(),
                ))
        db.commit()

        try:
            db.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_audit_logs_agent_time ON audit_logs(agent_id, created_at)"
            ))
            db.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_issued_tokens_agent ON issued_tokens(agent_id)"
            ))
            db.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_issued_tokens_active ON issued_tokens(active, expires_at)"
            ))
            db.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_issued_tokens_refresh_jti ON issued_tokens(refresh_jti)"
            ))
            db.commit()
        except Exception:
            db.rollback()


def get_connection():
    return SessionLocal()


def close_connection() -> None:
    pass


def row_to_dict(row) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    if isinstance(row, dict):
        return row
    return {c.key: getattr(row, c.key) for c in row.__table__.columns}


def reset_documents() -> List[Dict[str, Any]]:
    with SessionLocal() as db:
        db.execute(delete(DocumentRow))
        db.commit()
        for doc in settings.DEFAULT_DOCS:
            db.add(DocumentRow(
                doc_id=doc["doc_id"],
                content=doc["content"],
                sensitivity=doc["sensitivity"],
                updated_by="system",
                updated_at=utc_now(),
            ))
        db.commit()
        return list_documents()


def list_documents() -> List[Dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.execute(
            select(DocumentRow.doc_id, DocumentRow.sensitivity, DocumentRow.updated_by, DocumentRow.updated_at)
            .order_by(DocumentRow.doc_id)
        ).all()
    _doc_names = {
        "public_brief": "Public Brief",
        "team_notes": "Team Notes",
        "admin_playbook": "Admin Playbook",
    }
    return [
        {
            "resource_id": "doc:" + r[0],
            "name": _doc_names.get(r[0], r[0].replace("_", " ").title()),
            "doc_id": r[0],
            "sensitivity": r[1],
            "updated_by": r[2],
            "updated_at": r[3],
        }
        for r in rows
    ]


def get_document(doc_id: str) -> Optional[Dict[str, Any]]:
    with SessionLocal() as db:
        row = db.get(DocumentRow, doc_id)
    if not row:
        return None
    return {
        "doc_id": row.doc_id,
        "content": row.content,
        "sensitivity": row.sensitivity,
        "updated_by": row.updated_by,
        "updated_at": row.updated_at,
    }


def upsert_document(doc_id: str, content: str, sensitivity: str, updated_by: str) -> Dict[str, Any]:
    timestamp = utc_now()
    with SessionLocal() as db:
        existing = db.get(DocumentRow, doc_id)
        if existing:
            existing.content = content
            existing.sensitivity = sensitivity
            existing.updated_by = updated_by
            existing.updated_at = timestamp
        else:
            db.add(DocumentRow(
                doc_id=doc_id, content=content, sensitivity=sensitivity,
                updated_by=updated_by, updated_at=timestamp,
            ))
        db.commit()
    document = get_document(doc_id)
    if not document:
        raise RuntimeError("Document write failed unexpectedly.")
    return document


def get_token_state(jti: str) -> Optional[Dict[str, Any]]:
    with SessionLocal() as db:
        row = db.get(IssuedTokenRow, jti)
    if not row:
        return None
    return {
        "jti": row.jti,
        "agent_id": row.agent_id,
        "issued_at": row.issued_at,
        "expires_at": row.expires_at,
        "active": row.active,
        "bound_ip": row.bound_ip,
        "usage_limit": row.usage_limit,
        "usage_count": row.usage_count,
    }


def revoke_token(jti: str) -> bool:
    with SessionLocal() as db:
        row = db.get(IssuedTokenRow, jti)
        if not row:
            return False
        row.active = 0
        db.commit()
        return True


def clear_tokens() -> int:
    with SessionLocal() as db:
        count = db.execute(select(func.count()).select_from(IssuedTokenRow)).scalar() or 0
        db.execute(delete(IssuedTokenRow))
        db.commit()
    return count


def cleanup_expired_tokens() -> int:
    now = utc_now()
    with SessionLocal() as db:
        count = db.execute(
            select(func.count()).select_from(IssuedTokenRow)
            .where(and_(IssuedTokenRow.expires_at < now, IssuedTokenRow.active == 0))
        ).scalar() or 0
        db.execute(
            delete(IssuedTokenRow)
            .where(and_(IssuedTokenRow.expires_at < now, IssuedTokenRow.active == 0))
        )
        db.commit()
    return count


def get_system_snapshot() -> Dict[str, Any]:
    with SessionLocal() as db:
        agent_total = db.execute(select(func.count()).select_from(AgentRow)).scalar() or 0
        token_total = db.execute(select(func.count()).select_from(IssuedTokenRow)).scalar() or 0
        token_active = db.execute(
            select(func.count()).select_from(IssuedTokenRow).where(IssuedTokenRow.active == 1)
        ).scalar() or 0
        document_total = db.execute(select(func.count()).select_from(DocumentRow)).scalar() or 0

        role_rows = db.execute(
            select(AgentRow.role, func.count().label("count"))
            .group_by(AgentRow.role).order_by(desc("count"), AgentRow.role)
        ).all()
        status_rows = db.execute(
            select(AgentRow.status, func.count().label("count"))
            .group_by(AgentRow.status).order_by(desc("count"), AgentRow.status)
        ).all()
        sensitivity_rows = db.execute(
            select(DocumentRow.sensitivity, func.count().label("count"))
            .group_by(DocumentRow.sensitivity).order_by(desc("count"), DocumentRow.sensitivity)
        ).all()

    return {
        "agents": {
            "total": agent_total,
            "by_role": {r[0]: r[1] for r in role_rows},
            "by_status": {r[0]: r[1] for r in status_rows},
        },
        "tokens": {
            "total": token_total,
            "active": token_active,
            "inactive": token_total - token_active,
        },
        "documents": {
            "total": document_total,
            "by_sensitivity": {r[0]: r[1] for r in sensitivity_rows},
        },
    }
