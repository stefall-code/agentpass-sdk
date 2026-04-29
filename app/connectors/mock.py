from typing import List, Dict, Any
from datetime import datetime, timedelta
import random
from .base import BaseConnector


class MockConnector(BaseConnector):
    """Mock 连接器基类"""
    
    def __init__(self, platform: str, region: str):
        super().__init__(platform, region, mock=True)
    
    async def connect(self) -> bool:
        self.connected = True
        return True
    
    async def fetch_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        events = []
        for i in range(limit):
            event = self._generate_mock_event()
            events.append(event)
        return events
    
    async def fetch_cost(self, days: int = 7) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "region": self.region,
            "days": days,
            "total_cost": round(random.uniform(10, 1000), 2),
            "token_usage": random.randint(1000, 100000),
            "request_count": random.randint(100, 10000),
            "daily_cost": [
                {
                    "date": (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d"),
                    "cost": round(random.uniform(1, 200), 2),
                    "tokens": random.randint(100, 20000)
                }
                for i in range(days)
            ]
        }
    
    async def fetch_pending_approvals(self) -> List[Dict[str, Any]]:
        approvals = []
        for i in range(random.randint(0, 10)):
            approval = {
                "id": f"approval_{self.platform}_{i}",
                "platform": self.platform,
                "region": self.region,
                "user": f"user{i}@example.com",
                "action": random.choice(["export_data", "access_sensitive", "high_cost"]),
                "resource": random.choice(["customer_data", "financial_report", "internal_docs"]),
                "risk_score": round(random.uniform(0.7, 1.0), 2),
                "created_at": (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
                "status": "pending"
            }
            approvals.append(approval)
        return approvals
    
    async def health_check(self) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "region": self.region,
            "status": "online",
            "latency": round(random.uniform(0.1, 1.0), 2),
            "last_connected": datetime.now().isoformat()
        }
    
    def _generate_mock_event(self) -> Dict[str, Any]:
        """生成模拟事件"""
        risk_levels = ["low", "medium", "high", "critical"]
        actions = ["chat_completion", "data_access", "file_upload", "model_training"]
        resources = ["general_query", "customer_data", "financial_data", "internal_docs"]
        
        risk_score = random.random()
        risk_level = next((r for r in risk_levels if {
            "low": risk_score < 0.3,
            "medium": 0.3 <= risk_score < 0.7,
            "high": 0.7 <= risk_score < 0.9,
            "critical": risk_score >= 0.9
        }[r]), "low")
        
        return {
            "id": f"event_{self.platform}_{random.randint(1000, 9999)}",
            "timestamp": (datetime.now() - timedelta(hours=random.randint(0, 24))).isoformat(),
            "platform": self.platform,
            "region": self.region,
            "user": f"user{random.randint(1, 100)}@example.com",
            "team": f"team{random.randint(1, 10)}",
            "action": random.choice(actions),
            "resource": random.choice(resources),
            "prompt": "This is a test prompt",
            "output": "This is a test output",
            "risk": risk_score,
            "risk_level": risk_level,
            "approval_required": risk_score > 0.7,
            "approval_status": "pending" if risk_score > 0.7 else "none",
            "cost": round(random.uniform(0.01, 10.0), 2),
            "token_usage": random.randint(10, 1000),
            "blocked": risk_score > 0.9,
            "reason": "High risk content detected" if risk_score > 0.9 else ""
        }
