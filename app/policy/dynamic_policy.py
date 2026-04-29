from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any, List


RISK_THRESHOLD = 0.7
CHAIN_DEPTH_LIMIT = 3
WORK_HOUR_START = 9
WORK_HOUR_END = 18

PLATFORM_RISK_WEIGHT = {
    "feishu": 0.1,
    "web": 0.3,
    "api": 0.5,
}

ENTERPRISE_DATA_PREFIXES = ("read:feishu_table", "read:enterprise", "read:salary")


@dataclass
class DynamicPolicyResult:
    allowed: bool
    reason: str
    rule_id: str = ""
    trace: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.trace is None:
            self.trace = []


def evaluate_dynamic_policy(context: Dict[str, Any]) -> DynamicPolicyResult:
    trace: List[Dict[str, Any]] = []

    agent_id = context.get("agent_id", "")
    user = context.get("user", "")
    action = context.get("action", "")
    resource = context.get("resource", "")
    risk_score = float(context.get("risk_score", 0.0))
    timestamp = context.get("timestamp", "")
    chain_length = int(context.get("chain_length", 1))

    trace.append({"rule": "input_parsed", "passed": True, "detail": f"agent={agent_id}, user={user}, action={action}, risk={risk_score}, chain_len={chain_length}"})

    if risk_score > RISK_THRESHOLD:
        trace.append({"rule": "high_risk_intercept", "passed": False, "detail": f"risk_score={risk_score} > threshold={RISK_THRESHOLD}"})
        return DynamicPolicyResult(
            allowed=False,
            reason=f"Dynamic policy violation: high risk score ({risk_score:.2f} > {RISK_THRESHOLD})",
            rule_id="dynamic_high_risk",
            trace=trace,
        )
    trace.append({"rule": "high_risk_intercept", "passed": True, "detail": f"risk_score={risk_score} <= {RISK_THRESHOLD}"})

    if chain_length > CHAIN_DEPTH_LIMIT:
        trace.append({"rule": "deep_chain_limit", "passed": False, "detail": f"chain_length={chain_length} > limit={CHAIN_DEPTH_LIMIT}"})
        return DynamicPolicyResult(
            allowed=False,
            reason=f"Dynamic policy violation: chain too deep ({chain_length} > {CHAIN_DEPTH_LIMIT})",
            rule_id="dynamic_deep_chain",
            trace=trace,
        )
    trace.append({"rule": "deep_chain_limit", "passed": True, "detail": f"chain_length={chain_length} <= {CHAIN_DEPTH_LIMIT}"})

    is_sensitive_action = "write" in action.lower() or "delete" in action.lower() or "export" in action.lower()
    is_feishu_gateway = action.startswith(("write:im", "write:feishu_message", "write:doc", "read:feishu", "read:calendar", "write:calendar"))

    if is_sensitive_action and user != "admin" and not is_feishu_gateway:
        trace.append({"rule": "sensitive_action_restriction", "passed": False, "detail": f"action='{action}' is sensitive and user='{user}' != 'admin'"})
        return DynamicPolicyResult(
            allowed=False,
            reason=f"Dynamic policy violation: sensitive action '{action}' requires admin user (current: '{user}')",
            rule_id="dynamic_sensitive_action",
            trace=trace,
        )
    trace.append({"rule": "sensitive_action_restriction", "passed": True, "detail": f"action='{action}' passed sensitive check"})

    if is_sensitive_action and not is_feishu_gateway:
        try:
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            else:
                dt = datetime.now(timezone.utc)
            hour = dt.hour
        except Exception:
            hour = datetime.now(timezone.utc).hour

        if hour < WORK_HOUR_START or hour >= WORK_HOUR_END:
            trace.append({"rule": "off_hours_restriction", "passed": False, "detail": f"hour={hour}, sensitive action outside {WORK_HOUR_START}:00-{WORK_HOUR_END}:00"})
            return DynamicPolicyResult(
                allowed=False,
                reason=f"Dynamic policy violation: sensitive action '{action}' not allowed outside work hours ({WORK_HOUR_START}:00-{WORK_HOUR_END}:00), current hour={hour}",
                rule_id="dynamic_off_hours",
                trace=trace,
            )
        trace.append({"rule": "off_hours_restriction", "passed": True, "detail": f"hour={hour}, within work hours"})
    else:
        trace.append({"rule": "off_hours_restriction", "passed": True, "detail": "non-sensitive action, time check skipped"})

    trace.append({"rule": "all_policies_passed", "passed": True, "detail": "All dynamic policy checks passed"})

    platform = context.get("platform", "web")
    platform_risk = PLATFORM_RISK_WEIGHT.get(platform, 0.3)
    action = context.get("action", "")

    if platform != "feishu" and any(action.startswith(p) for p in ENTERPRISE_DATA_PREFIXES):
        platform_risk += 0.2
        trace.append({"rule": "platform_enterprise_data", "passed": False, "detail": f"platform={platform} accessing enterprise data, risk +0.2 → {platform_risk:.2f}"})
        risk_score = float(context.get("risk_score", 0.0)) + platform_risk
        if risk_score > RISK_THRESHOLD:
            return DynamicPolicyResult(
                allowed=False,
                reason=f"Dynamic policy violation: non-feishu platform ({platform}) accessing enterprise data, adjusted risk ({risk_score:.2f}) exceeds threshold ({RISK_THRESHOLD})",
                rule_id="dynamic_platform_enterprise",
                trace=trace,
            )
    else:
        trace.append({"rule": "platform_risk_check", "passed": True, "detail": f"platform={platform}, risk_weight={platform_risk}"})

    return DynamicPolicyResult(
        allowed=True,
        reason="All dynamic policy checks passed",
        rule_id="dynamic_passed",
        trace=trace,
    )
