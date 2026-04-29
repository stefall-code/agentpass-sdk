from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app import permission

from .dynamic_policy import evaluate_dynamic_policy, DynamicPolicyResult


@dataclass
class PolicyCheckStep:
    step_id: str
    name: str
    passed: bool
    reason: str = ""
    detail: str = ""


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    rule_id: str = ""
    trace: list[PolicyCheckStep] = field(default_factory=list)


@dataclass
class PolicyRule:
    rule_id: str
    priority: int = 0
    description: str = ""
    condition: Optional[str] = None
    time_restriction: Optional[dict] = None
    attribute_match: Optional[dict] = None


BUILTIN_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="admin_override",
        priority=100,
        description="Admin角色拥有最高权限覆盖",
        condition="role==admin",
    ),
    PolicyRule(
        rule_id="business_hours_sensitive",
        priority=50,
        description="敏感操作仅允许工作时间(8:00-22:00 UTC)",
        time_restriction={"start_hour": 8, "end_hour": 22},
        condition="sensitivity==confidential",
    ),
    PolicyRule(
        rule_id="cross_department_deny",
        priority=40,
        description="跨部门资源访问需要显式授权",
        attribute_match={"require_match": "department"},
    ),
]


def _is_business_hours(time_restriction: dict) -> bool:
    now = datetime.now(timezone.utc)
    start = time_restriction.get("start_hour", 0)
    end = time_restriction.get("end_hour", 24)
    return start <= now.hour < end


def _check_attribute_match(agent_attrs: dict, resource_meta: dict, rule: PolicyRule) -> bool:
    if not rule.attribute_match:
        return True
    match_field = rule.attribute_match.get("require_match")
    if not match_field:
        return True
    agent_val = agent_attrs.get(match_field)
    resource_val = resource_meta.get(match_field)
    if agent_val is None or resource_val is None:
        return True
    return agent_val == resource_val


def evaluate(
    agent: dict | None,
    action: str,
    resource: str,
    resource_meta: dict | None = None,
) -> PolicyDecision:
    trace: list[PolicyCheckStep] = []

    if not agent:
        trace.append(PolicyCheckStep("agent_exist", "Agent 身份验证", False, "Unknown agent.", "请求中未提供有效的 Agent 身份"))
        return PolicyDecision(False, "Unknown agent.", "no_agent", trace)
    trace.append(PolicyCheckStep("agent_exist", "Agent 身份验证", True, "Agent identified", f"Agent: {agent.get('agent_id', '?')}"))

    if agent["status"] != "active":
        trace.append(PolicyCheckStep("agent_status", "Agent 状态检查", False, f"Agent status is {agent['status']}.", f"当前状态: {agent['status']}，仅 active 状态可执行操作"))
        return PolicyDecision(False, f"Agent status is {agent['status']}.", "inactive_agent", trace)
    trace.append(PolicyCheckStep("agent_status", "Agent 状态检查", True, "Agent is active", "状态正常，允许继续"))

    if agent["role"] == "admin":
        if not permission.check_permission(agent["role"], action):
            trace.append(PolicyCheckStep("admin_perm", "Admin 权限检查", False, f"Role 'admin' is not allowed to perform '{action}'.", f"即使 Admin 角色也不具备 '{action}' 权限"))
            return PolicyDecision(False, f"Role 'admin' is not allowed to perform '{action}'.", "admin_no_perm", trace)
        trace.append(PolicyCheckStep("admin_override", "Admin 权限覆盖", True, "Policy check passed (admin override).", "Admin 角色拥有最高权限，跳过后续检查"))
        return PolicyDecision(True, "Policy check passed (admin override).", "admin_override", trace)
    trace.append(PolicyCheckStep("admin_check", "Admin 权限检查", True, "Non-admin agent", f"角色为 {agent['role']}，继续常规策略检查"))

    if not permission.check_permission(agent["role"], action):
        trace.append(PolicyCheckStep("rbac_check", "RBAC 角色权限检查", False, f"Role '{agent['role']}' is not allowed to perform '{action}'.", f"角色 '{agent['role']}' 的权限列表中不包含 '{action}'"))
        return PolicyDecision(False, f"Role '{agent['role']}' is not allowed to perform '{action}'.", "rbac_deny", trace)
    trace.append(PolicyCheckStep("rbac_check", "RBAC 角色权限检查", True, f"Role '{agent['role']}' has permission '{action}'", "角色权限验证通过"))

    attributes = agent.get("attributes", {})
    allowed_resources = attributes.get("allowed_resources")
    if allowed_resources and "*" not in allowed_resources and resource not in allowed_resources:
        trace.append(PolicyCheckStep("allowlist", "资源白名单检查", False, f"Resource '{resource}' is outside the agent allowlist.", f"Agent 的白名单: {allowed_resources}，不包含 '{resource}'"))
        return PolicyDecision(False, f"Resource '{resource}' is outside the agent allowlist.", "allowlist_deny", trace)
    trace.append(PolicyCheckStep("allowlist", "资源白名单检查", True, f"Resource '{resource}' is in allowlist", "资源白名单验证通过"))

    resource_meta = resource_meta or {}
    sensitivity = resource_meta.get("sensitivity")

    if sensitivity == "confidential" and agent["role"] != "admin":
        trace.append(PolicyCheckStep("confidential", "敏感级别检查", False, "Confidential resources require admin role.", "资源敏感级别为 'confidential'，仅 Admin 角色可访问"))
        return PolicyDecision(False, "Confidential resources require admin role.", "confidential_deny", trace)
    if sensitivity:
        trace.append(PolicyCheckStep("sensitivity", "敏感级别检查", True, f"Sensitivity '{sensitivity}' is accessible", f"资源敏感级别 '{sensitivity}' 在当前角色权限范围内"))
    else:
        trace.append(PolicyCheckStep("sensitivity", "敏感级别检查", True, "No sensitivity restriction", "资源无敏感级别标记"))

    if resource.startswith("admin:") and agent["role"] != "admin":
        trace.append(PolicyCheckStep("admin_resource", "管理资源检查", False, "Administrative resources require admin role.", f"资源 '{resource}' 属于管理资源，需要 Admin 角色"))
        return PolicyDecision(False, "Administrative resources require admin role.", "admin_resource_deny", trace)
    if resource.startswith("admin:"):
        trace.append(PolicyCheckStep("admin_resource", "管理资源检查", True, "Admin resource accessible", "Admin 角色可访问管理资源"))

    if sensitivity == "confidential":
        time_rule = next((r for r in BUILTIN_RULES if r.rule_id == "business_hours_sensitive"), None)
        if time_rule and time_rule.time_restriction:
            if not _is_business_hours(time_rule.time_restriction):
                trace.append(PolicyCheckStep("time_restriction", "时间策略检查", False,
                    f"Sensitive operations on '{sensitivity}' resources are only allowed during business hours (08:00-22:00 UTC).",
                    "当前时间不在允许范围内（08:00-22:00 UTC）"))
                return PolicyDecision(
                    False,
                    f"Sensitive operations on '{sensitivity}' resources are only allowed during business hours (08:00-22:00 UTC).",
                    "time_restriction",
                    trace,
                )
            trace.append(PolicyCheckStep("time_restriction", "时间策略检查", True, "Within business hours", "当前时间在允许范围内"))

    cross_dept_rule = next((r for r in BUILTIN_RULES if r.rule_id == "cross_department_deny"), None)
    if cross_dept_rule:
        if not _check_attribute_match(attributes, resource_meta, cross_dept_rule):
            trace.append(PolicyCheckStep("abac_check", "ABAC 属性匹配检查", False,
                "Cross-department access denied. Agent department does not match resource department.",
                "Agent 的部门属性与资源的部门属性不匹配"))
            return PolicyDecision(
                False,
                "Cross-department access denied. Agent department does not match resource department.",
                "abac_deny",
                trace,
            )
        trace.append(PolicyCheckStep("abac_check", "ABAC 属性匹配检查", True, "Attribute match passed", "属性匹配验证通过"))

    trace.append(PolicyCheckStep("final", "策略评估完成", True, "Policy check passed.", "所有策略检查均已通过"))
    return PolicyDecision(True, "Policy check passed.", "passed", trace)


__all__ = [
    "evaluate_dynamic_policy", "DynamicPolicyResult",
    "evaluate", "PolicyDecision", "PolicyCheckStep", "PolicyRule", "BUILTIN_RULES",
]
