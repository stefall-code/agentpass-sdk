"""
手动计算声誉分数的简单脚本，直接操作数据库
"""
import sys
sys.path.insert(0, '.')

import json
from datetime import timedelta, timezone, datetime
from sqlalchemy import select, func, and_
from app.db import SessionLocal
from app.models import AgentReputationRow, AuditLogRow, AgentRow

def compute_score(agent_id):
    with SessionLocal() as db:
        # 检查是否已存在声誉记录
        row = db.execute(
            select(AgentReputationRow).where(AgentReputationRow.agent_id == agent_id)
        ).scalar_one_or_none()

        # 计算允许率
        total = db.execute(
            select(func.count()).select_from(AuditLogRow)
            .where(AuditLogRow.agent_id == agent_id)
        ).scalar() or 0
        if total == 0:
            allow_rate = 0.5
        else:
            allowed = db.execute(
                select(func.count()).select_from(AuditLogRow)
                .where(AuditLogRow.agent_id == agent_id, AuditLogRow.decision == "allow")
            ).scalar() or 0
            allow_rate = allowed / total

        # 计算拒绝连续次数
        rows = db.execute(
            select(AuditLogRow.decision)
            .where(AuditLogRow.agent_id == agent_id)
            .order_by(AuditLogRow.id.desc())
            .limit(20)
        ).scalars().all()
        denial_streak = 0
        for d in rows:
            if d == "deny":
                denial_streak += 1
            else:
                break

        # 计算年龄
        agent = db.execute(
            select(AgentRow).where(AgentRow.agent_id == agent_id)
        ).scalar_one_or_none()
        days_since_creation = 0.0
        if agent:
            try:
                created = datetime.fromisoformat(agent.created_at.replace("Z", "+00:00"))
                days_since_creation = (datetime.now(timezone.utc) - created).days
                days_since_creation = float(max(days_since_creation, 0))
            except Exception:
                pass

        # 计算可疑模式
        suspicious_count = 0
        recent_window = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        distinct_resources = db.execute(
            select(func.count(func.distinct(AuditLogRow.resource)))
            .where(and_(AuditLogRow.agent_id == agent_id, AuditLogRow.created_at >= recent_window))
        ).scalar() or 0
        if distinct_resources >= 8:
            suspicious_count += 1

        distinct_ips = db.execute(
            select(func.count(func.distinct(AuditLogRow.ip_address)))
            .where(AuditLogRow.agent_id == agent_id)
        ).scalar() or 0
        if distinct_ips >= 3:
            suspicious_count += 1

        # 计算声誉分数
        score = (
            70.0
            + (allow_rate - 0.5) * 40.0
            - denial_streak * 5.0
            + min(days_since_creation * 0.1, 5.0)
            - suspicious_count * 8.0
        )
        score = max(0.0, min(100.0, score))

        # 计算趋势
        prev_score = row.score if row else 70.0
        if score > prev_score + 2:
            trend = "rising"
        elif score < prev_score - 2:
            trend = "falling"
        else:
            trend = "stable"

        # 更新历史记录
        history = json.loads(row.history_json) if row and row.history_json else []
        history.append({"score": round(score, 2), "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
        if len(history) > 720:
            history = history[-720:]

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 保存到数据库
        if not row:
            row = AgentReputationRow(
                agent_id=agent_id,
                score=score,
                allow_rate=allow_rate,
                denial_streak=denial_streak,
                suspicious_pattern_count=suspicious_count,
                consistency_bonus=0.0,
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
            row.consistency_bonus = 0.0
            row.trend = trend
            row.last_computed_at = now_str
            row.history_json = json.dumps(history)
        db.commit()

        print(f"Agent {agent_id}: 声誉分数 = {round(score, 2)}, 趋势 = {trend}")

# 获取所有 agent 并计算声誉分数
def recompute_all():
    with SessionLocal() as db:
        agents = db.execute(
            select(AgentRow.agent_id)
        ).scalars().all()

    print(f"开始计算 {len(agents)} 个 agent 的声誉分数...")
    for agent_id in agents:
        try:
            compute_score(agent_id)
        except Exception as e:
            print(f"计算 agent {agent_id} 的声誉分数时出错: {e}")
    print("声誉分数计算完成！")

if __name__ == "__main__":
    recompute_all()