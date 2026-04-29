from typing import Dict, List, Optional
from datetime import datetime, timedelta
import random


class ApprovalEngine:
    """统一审批引擎"""
    
    # 审批规则
    APPROVAL_RULES = [
        {"name": "high_risk", "condition": lambda req: req.get("risk", 0) > 0.75},
        {"name": "export_data", "condition": lambda req: req.get("action") == "export_data"},
        {"name": "high_cost", "condition": lambda req: req.get("cost", 0) > 50},
        {"name": "finance_resource", "condition": lambda req: "finance" in req.get("resource", "")},
        {"name": "external_email", "condition": lambda req: "email" in req.get("action", "").lower() and "external" in req.get("action", "").lower()},
        {"name": "delete_data", "condition": lambda req: req.get("action") == "delete_data"},
    ]
    
    # 审批人
    APPROVERS = {
        "default": ["manager@corp.com"],
        "finance": ["finance@corp.com"],
        "admin": ["admin@corp.com"],
    }
    
    def __init__(self):
        self.approvals = {}
        self.next_id = 1
    
    def check_approval_required(self, request: Dict) -> Dict:
        """检查是否需要审批"""
        triggered_rules = []
        approval_required = False
        
        for rule in self.APPROVAL_RULES:
            if rule["condition"](request):
                triggered_rules.append(rule["name"])
                approval_required = True
        
        # 确定审批人
        approvers = []
        if "high_cost" in triggered_rules or "finance_resource" in triggered_rules:
            approvers.extend(self.APPROVERS["finance"])
        if "delete_data" in triggered_rules:
            approvers.extend(self.APPROVERS["admin"])
            approvers.extend(self.APPROVERS["default"])
        if not approvers:
            approvers.extend(self.APPROVERS["default"])
        
        # 去重
        approvers = list(set(approvers))
        
        return {
            "approval_required": approval_required,
            "triggered_rules": triggered_rules,
            "approvers": approvers,
            "required_approvals": len(approvers),
        }
    
    def create_approval(self, request: Dict) -> Dict:
        """创建审批请求"""
        check_result = self.check_approval_required(request)
        
        if not check_result["approval_required"]:
            return {
                "id": f"approval_{self.next_id}",
                "status": "approved",
                "message": "No approval required"
            }
        
        approval_id = f"approval_{self.next_id}"
        self.next_id += 1
        
        approval = {
            "id": approval_id,
            "platform": request.get("platform", "unknown"),
            "region": request.get("region", "unknown"),
            "user": request.get("user", "unknown"),
            "action": request.get("action", "unknown"),
            "resource": request.get("resource", "unknown"),
            "risk_score": request.get("risk", 0),
            "cost": request.get("cost", 0),
            "triggered_rules": check_result["triggered_rules"],
            "approvers": check_result["approvers"],
            "required_approvals": check_result["required_approvals"],
            "approved_by": [],
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=24)).isoformat(),
            "reason": request.get("reason", "")
        }
        
        self.approvals[approval_id] = approval
        return approval
    
    def approve(self, approval_id: str, approver: str) -> Dict:
        """批准审批"""
        if approval_id not in self.approvals:
            return {"error": "Approval not found"}
        
        approval = self.approvals[approval_id]
        
        if approval["status"] != "pending":
            return {"error": f"Approval is already {approval['status']}"}
        
        if approver not in approval["approvers"]:
            return {"error": "Approver not authorized"}
        
        if approver in approval["approved_by"]:
            return {"error": "Approver has already approved"}
        
        approval["approved_by"].append(approver)
        
        if len(approval["approved_by"]) >= approval["required_approvals"]:
            approval["status"] = "approved"
            approval["decided_at"] = datetime.now().isoformat()
            approval["decided_by"] = approver
        
        return approval
    
    def reject(self, approval_id: str, approver: str) -> Dict:
        """拒绝审批"""
        if approval_id not in self.approvals:
            return {"error": "Approval not found"}
        
        approval = self.approvals[approval_id]
        
        if approval["status"] != "pending":
            return {"error": f"Approval is already {approval['status']}"}
        
        if approver not in approval["approvers"]:
            return {"error": "Approver not authorized"}
        
        approval["status"] = "rejected"
        approval["decided_at"] = datetime.now().isoformat()
        approval["decided_by"] = approver
        
        return approval
    
    def get_pending_approvals(self) -> List[Dict]:
        """获取待审批列表"""
        pending = []
        now = datetime.now()
        
        for approval in self.approvals.values():
            if approval["status"] == "pending":
                # 检查是否过期
                expires_at = datetime.fromisoformat(approval["expires_at"])
                if now > expires_at:
                    approval["status"] = "expired"
                    approval["decided_at"] = now.isoformat()
                else:
                    pending.append(approval)
        
        return pending
    
    def get_approval(self, approval_id: str) -> Optional[Dict]:
        """获取审批详情"""
        return self.approvals.get(approval_id)
    
    def generate_mock_approvals(self, count: int = 10) -> List[Dict]:
        """生成模拟审批数据"""
        mock_approvals = []
        
        for i in range(count):
            request = {
                "platform": random.choice(["chatgpt", "feishu", "qwen", "claude"]),
                "region": random.choice(["us", "cn"]),
                "user": f"user{i}@example.com",
                "action": random.choice(["export_data", "access_sensitive", "high_cost", "delete_data"]),
                "resource": random.choice(["customer_data", "financial_report", "internal_docs"]),
                "risk": round(random.uniform(0.7, 1.0), 2),
                "cost": random.uniform(10, 100),
                "reason": "High risk operation"
            }
            
            approval = self.create_approval(request)
            if approval.get("status") == "pending":
                mock_approvals.append(approval)
        
        return mock_approvals
