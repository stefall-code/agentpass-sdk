from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


PLATFORM_RISK_WEIGHT = {
    "feishu": 0.1,
    "web": 0.3,
    "api": 0.5,
}

ENTERPRISE_DATA_PREFIXES = ("read:feishu_table", "read:enterprise", "read:salary")


@dataclass
class PlatformRequest:
    platform: str
    user_id: str
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    entry_point: str = ""
    risk_context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.entry_point:
            self.entry_point = {
                "feishu": "webhook",
                "web": "frontend",
                "api": "direct",
            }.get(self.platform, "unknown")
        if not self.risk_context:
            self.risk_context = {
                "time": self.timestamp,
                "platform": self.platform,
                "platform_risk": PLATFORM_RISK_WEIGHT.get(self.platform, 0.3),
            }


def normalize_request(
    raw_input: Dict[str, Any],
    default_platform: str = "web",
) -> PlatformRequest:
    platform = raw_input.get("platform", default_platform)
    if platform not in PLATFORM_RISK_WEIGHT:
        platform = default_platform

    user_id = raw_input.get("user_id", raw_input.get("open_id", "anonymous"))
    message = raw_input.get("message", raw_input.get("content", raw_input.get("text", "")))
    metadata = raw_input.get("metadata", {})
    timestamp = raw_input.get("timestamp", time.time())

    if "event" in raw_input:
        event = raw_input["event"]
        if isinstance(event, dict):
            platform = "feishu"
            user_id = event.get("sender", {}).get("sender_id", {}).get("open_id", user_id)
            msg_content = event.get("message", {}).get("content", "{}")
            if isinstance(msg_content, str):
                try:
                    import json
                    parsed = json.loads(msg_content)
                    message = parsed.get("text", message)
                except Exception:
                    pass

    return PlatformRequest(
        platform=platform,
        user_id=user_id,
        message=message,
        metadata=metadata,
        timestamp=timestamp,
    )


def calculate_platform_risk(platform: str, action: str) -> float:
    base_risk = PLATFORM_RISK_WEIGHT.get(platform, 0.3)
    if platform != "feishu" and any(action.startswith(p) for p in ENTERPRISE_DATA_PREFIXES):
        base_risk += 0.2
    return min(base_risk, 1.0)
