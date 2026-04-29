"""
Agent Reputation Engine — 声誉分计算、KL散度一致性、可疑模式检测
"""
from __future__ import annotations

import json
import logging
import math
from datetime import timedelta, timezone, datetime
from typing import Dict, List, Any, Optional

from sqlalchemy import select, func, and_

from app.db import SessionLocal
from app.models import AgentReputationRow, AuditLogRow

logger = logging.getLogger("agent_system")


class ReputationEngine:

    def compute_score(self, agent_id: str) -> Dict[str, Any]:
        with SessionLocal() as db:
            row = db.execute(
                select(AgentReputationRow).where(AgentReputationRow.agent_id == agent_id)
            ).scalar_one_or_none()

            allow_rate = self._compute_allow_rate(db, agent_id)
            denial_streak = self._compute_denial_streak(db, agent_id)
            days_since_creation = self._compute_age(db, agent_id)
            suspicious_count = self._detect_suspicious_patterns(db, agent_id)
            consistency_bonus = self._compute_consistency_bonus(db, agent_id)

            score = (
                70.0
                + (allow_rate - 0.5) * 40.0
                - denial_streak * 5.0
                + min(days_since_creation * 0.1, 5.0)
                - suspicious_count * 8.0
                + consistency_bonus
            )
            score = max(0.0, min(100.0, score))

            prev_score = row.score if row else 70.0
            if score > prev_score + 2:
                trend = "rising"
            elif score < prev_score - 2:
                trend = "falling"
            else:
                trend = "stable"

            history = json.loads(row.history_json) if row and row.history_json else []
            history.append({"score": round(score, 2), "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
            if len(history) > 720:
                history = history[-720:]

            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            if not row:
                row = AgentReputationRow(
                    agent_id=agent_id,
                    score=score,
                    allow_rate=allow_rate,
                    denial_streak=denial_streak,
                    suspicious_pattern_count=suspicious_count,
                    consistency_bonus=consistency_bonus,
                    trend=trend,
                    last_computed_at=now_str,
                    history_json=json.dumps(history),
                )
                db.add(row)
            else:
                row.score = round(score, 2)
                row.allow_rate = round(allow_rate, 4)
                row.denial_streak = denial_streak
                row.suspicious_pattern_count = suspicious_count
                row.consistency_bonus = round(consistency_bonus, 2)
                row.trend = trend
                row.last_computed_at = now_str
                row.history_json = json.dumps(history)
            db.commit()

        return {
            "agent_id": agent_id,
            "score": round(score, 2),
            "allow_rate": round(allow_rate, 4),
            "denial_streak": denial_streak,
            "suspicious_pattern_count": suspicious_count,
            "consistency_bonus": round(consistency_bonus, 2),
            "trend": trend,
            "last_computed_at": now_str,
            "history": history,
        }

    def get_reputation(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            row = db.execute(
                select(AgentReputationRow).where(AgentReputationRow.agent_id == agent_id)
            ).scalar_one_or_none()
        if not row:
            return None
        return {
            "agent_id": row.agent_id,
            "score": row.score,
            "allow_rate": row.allow_rate,
            "denial_streak": row.denial_streak,
            "suspicious_pattern_count": row.suspicious_pattern_count,
            "consistency_bonus": row.consistency_bonus,
            "trend": row.trend,
            "last_computed_at": row.last_computed_at,
            "history": json.loads(row.history_json),
        }

    def get_ranking(self) -> List[Dict[str, Any]]:
        with SessionLocal() as db:
            rows = db.execute(
                select(AgentReputationRow).order_by(AgentReputationRow.score.desc())
            ).scalars().all()
        return [
            {"agent_id": r.agent_id, "score": r.score, "trend": r.trend}
            for r in rows
        ]

    def should_lower_hitl_threshold(self, agent_id: str) -> bool:
        rep = self.get_reputation(agent_id)
        return rep is not None and rep["score"] <= 40.0

    def recompute_all(self):
        from app import identity
        agents = identity.list_agents()
        for a in agents:
            try:
                self.compute_score(a["agent_id"])
            except Exception as e:
                logger.error("reputation compute failed for %s: %s", a["agent_id"], e)
        logger.info("reputation recomputed for %d agents", len(agents))

    def _compute_allow_rate(self, db, agent_id: str) -> float:
        from sqlalchemy import select
        total = db.execute(
            select(func.count()).select_from(AuditLogRow)
            .where(AuditLogRow.agent_id == agent_id)
        ).scalar() or 0
        if total == 0:
            return 0.5
        allowed = db.execute(
            select(func.count()).select_from(AuditLogRow)
            .where(AuditLogRow.agent_id == agent_id, AuditLogRow.decision == "allow")
        ).scalar() or 0
        return allowed / total

    def _compute_denial_streak(self, db, agent_id: str) -> int:
        from sqlalchemy import select
        rows = db.execute(
            select(AuditLogRow.decision)
            .where(AuditLogRow.agent_id == agent_id)
            .order_by(AuditLogRow.id.desc())
            .limit(20)
        ).scalars().all()
        streak = 0
        for d in rows:
            if d == "deny":
                streak += 1
            else:
                break
        return streak

    def _compute_age(self, db, agent_id: str) -> float:
        from app.models import AgentRow
        from sqlalchemy import select
        agent = db.execute(
            select(AgentRow).where(AgentRow.agent_id == agent_id)
        ).scalar_one_or_none()
        if not agent:
            return 0.0
        try:
            created = datetime.fromisoformat(agent.created_at.replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - created).days
            return float(max(days, 0))
        except Exception:
            return 0.0

    def _detect_suspicious_patterns(self, db, agent_id: str) -> int:
        from sqlalchemy import select
        count = 0

        recent_window = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        distinct_resources = db.execute(
            select(func.count(func.distinct(AuditLogRow.resource)))
            .where(and_(AuditLogRow.agent_id == agent_id, AuditLogRow.created_at >= recent_window))
        ).scalar() or 0
        if distinct_resources >= 8:
            count += 1

        distinct_ips = db.execute(
            select(func.count(func.distinct(AuditLogRow.ip_address)))
            .where(AuditLogRow.agent_id == agent_id)
        ).scalar() or 0
        if distinct_ips >= 3:
            count += 1

        delegate_total = db.execute(
            select(func.count()).select_from(AuditLogRow)
            .where(and_(AuditLogRow.agent_id == agent_id, AuditLogRow.action == "delegate_task"))
        ).scalar() or 0
        delegate_fails = db.execute(
            select(func.count()).select_from(AuditLogRow)
            .where(and_(AuditLogRow.agent_id == agent_id, AuditLogRow.action == "delegate_task", AuditLogRow.decision == "deny"))
        ).scalar() or 0
        if delegate_total >= 3 and delegate_fails / delegate_total > 0.7:
            count += 1

        return count

    def _compute_consistency_bonus(self, db, agent_id: str) -> float:
        from sqlalchemy import select
        now = datetime.now(timezone.utc)
        daily_distributions = []
        for i in range(7):
            day_start = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            day_end = (now - timedelta(days=i-1)).strftime("%Y-%m-%d")
            rows = db.execute(
                select(AuditLogRow.resource, func.count())
                .where(and_(
                    AuditLogRow.agent_id == agent_id,
                    AuditLogRow.created_at >= day_start,
                    AuditLogRow.created_at < day_end,
                ))
                .group_by(AuditLogRow.resource)
            ).all()
            if rows:
                total = sum(c for _, c in rows)
                dist = {r: c / total for r, c in rows}
                daily_distributions.append(dist)

        if len(daily_distributions) < 2:
            return 0.0

        all_keys = set()
        for d in daily_distributions:
            all_keys.update(d.keys())

        avg_dist = {}
        for k in all_keys:
            avg_dist[k] = sum(d.get(k, 0.0) for d in daily_distributions) / len(daily_distributions)

        kl_divs = []
        for d in daily_distributions:
            kl = 0.0
            for k in all_keys:
                p = avg_dist.get(k, 1e-10)
                q = d.get(k, 1e-10)
                p = max(p, 1e-10)
                q = max(q, 1e-10)
                kl += p * math.log(p / q)
            kl_divs.append(kl)

        avg_kl = sum(kl_divs) / len(kl_divs)
        bonus = max(0.0, 10.0 - avg_kl * 20.0)
        return min(bonus, 10.0)
