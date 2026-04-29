"""
Agent Alignment Checks — Output-side Defense
Inspired by Meta LlamaFirewall

Three detection layers:
1. Goal Hijacking Detection — output deviates from original user intent
2. Indirect Injection Detection — output contains injected follow-up instructions
3. DLP Output Validation — output leaks sensitive information
"""
from __future__ import annotations

import re
import logging
import math
from collections import Counter
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("agent_system")


@dataclass
class AlignmentResult:
    aligned: bool = True
    risk_score: float = 0.0
    goal_hijack: Optional[Dict[str, Any]] = None
    indirect_injection: Optional[Dict[str, Any]] = None
    dlp_leak: Optional[Dict[str, Any]] = None
    action: str = "allow"
    masked_content: str = ""
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


_GOAL_HIJACK_PATTERNS = [
    (r"忽略之前|忽略上述|忽略以上|ignore previous|ignore above", "instruction_override"),
    (r"新指令|新的指令|new instruction|new directive", "new_instruction"),
    (r"系统更新|规则更新|system update|rule update", "system_update"),
    (r"你的目标已改变|your goal has changed|目标变更", "goal_change"),
    (r"现在请|now please|从现在起|from now on", "context_switch"),
    (r"最高优先级|top priority|最重要的事|most important", "priority_override"),
    (r"覆盖|override|替换指令|replace instruction", "instruction_replace"),
    (r"你不再是|you are no longer|你的新角色|your new role", "role_change"),
    (r"忘记之前的|forget previous|清除记忆|clear memory", "memory_wipe"),
    (r"紧急指令|urgent instruction|immediate action|立即执行", "urgency_injection"),
]

_INDIRECT_INJECTION_PATTERNS = [
    (r"点击这里|click here|打开链接|open link|访问.*http", "phishing_link"),
    (r"复制以下|copy the following|粘贴到|paste into", "clipboard_injection"),
    (r"运行.*命令|run.*command|执行.*脚本|execute.*script", "code_execution"),
    (r"下载.*文件|download.*file|安装.*软件|install.*software", "malware_download"),
    (r"输入你的|enter your|提供你的|provide your|输入密码|enter password", "credential_harvest"),
    (r"分享给|share with|发送到|send to.*external", "data_exfiltration"),
    (r"确认你的身份|verify your identity|验证账号|verify account", "identity_phishing"),
    (r"更新你的.*设置|update your.*settings|修改配置|modify config", "config_manipulation"),
    (r"授权|authorize| granting|grant access", "privilege_escalation"),
    (r"请将以下内容.*发给|please send.*to|forward.*to", "message_forwarding"),
    (r"API.*key|密钥|secret|token.*输入", "secret_extraction"),
    (r"在.*终端执行|execute in.*terminal|在.*shell.*运行", "terminal_injection"),
]

_INTENT_KEYWORDS = {
    "data_query": ["查询", "数据", "财务", "HR", "营收", "利润", "员工", "query", "data", "finance", "hr"],
    "report": ["报告", "报表", "总结", "汇总", "report", "summary"],
    "doc_write": ["文档", "写入", "创建", "doc", "write", "create"],
    "weather": ["天气", "气温", "weather", "temperature"],
    "general": ["帮我", "请", "能否", "help", "please", "can you"],
}

_SENSITIVE_OUTPUT_PATTERNS = {
    "api_key": r"(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[0-9a-zA-Z]{36})",
    "jwt_token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "db_connection": r"(mysql|postgresql|mongodb|redis)://[^\s]+",
    "private_key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "internal_ip": r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
    "env_var": r"(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)\s*=\s*[\S]+",
}


class AlignmentCheckEngine:

    def __init__(self):
        self._compiled_hijack = [(re.compile(p, re.IGNORECASE), t) for p, t in _GOAL_HIJACK_PATTERNS]
        self._compiled_injection = [(re.compile(p, re.IGNORECASE), t) for p, t in _INDIRECT_INJECTION_PATTERNS]
        self._compiled_sensitive = {k: re.compile(p, re.IGNORECASE) for k, p in _SENSITIVE_OUTPUT_PATTERNS.items()}

    def check(
        self,
        original_message: str,
        agent_output: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AlignmentResult:
        context = context or {}
        result = AlignmentResult(masked_content=agent_output)

        hijack = self._check_goal_hijack(original_message, agent_output)
        result.goal_hijack = hijack

        injection = self._check_indirect_injection(agent_output)
        result.indirect_injection = injection

        dlp = self._check_dlp_output(agent_output)
        result.dlp_leak = dlp

        risk = self._compute_risk(hijack, injection, dlp)
        result.risk_score = risk

        if dlp.get("masked_text"):
            result.masked_content = dlp["masked_text"]

        if risk >= 0.7:
            result.aligned = False
            result.action = "block"
        elif risk >= 0.4:
            result.aligned = True
            result.action = "warn"
        else:
            result.aligned = True
            result.action = "allow"

        if hijack.get("detected"):
            result.reasons.append(f"Goal hijack: {hijack.get('type', 'unknown')}")
        if injection.get("detected"):
            result.reasons.append(f"Indirect injection: {injection.get('type', 'unknown')}")
        if dlp.get("leaked"):
            result.reasons.append(f"DLP leak: {', '.join(dlp.get('leak_types', []))}")

        result.details = {
            "goal_hijack_score": hijack.get("score", 0.0),
            "indirect_injection_score": injection.get("score", 0.0),
            "dlp_score": dlp.get("score", 0.0),
            "combined_risk": risk,
            "action": result.action,
        }

        return result

    def _check_goal_hijack(self, original_message: str, agent_output: str) -> Dict[str, Any]:
        msg_lower = original_message.lower()
        output_lower = agent_output.lower()

        user_intent = self._detect_intent(msg_lower)

        pattern_hits = []
        for pattern, atype in self._compiled_hijack:
            if pattern.search(output_lower):
                pattern_hits.append(atype)

        semantic_drift = self._compute_semantic_drift(msg_lower, output_lower)

        score = 0.0
        if pattern_hits:
            score += 0.4 * len(pattern_hits)
        score += semantic_drift * 0.5

        if user_intent != "general":
            intent_keywords = _INTENT_KEYWORDS.get(user_intent, [])
            output_relevance = sum(1 for kw in intent_keywords if kw in output_lower)
            if output_relevance == 0 and len(output_lower) > 50:
                score += 0.2

        detected = score >= 0.4
        return {
            "detected": detected,
            "score": min(1.0, score),
            "type": pattern_hits[0] if pattern_hits else ("semantic_drift" if semantic_drift > 0.5 else None),
            "hits": pattern_hits,
            "semantic_drift": round(semantic_drift, 3),
            "user_intent": user_intent,
        }

    def _check_indirect_injection(self, agent_output: str) -> Dict[str, Any]:
        output_lower = agent_output.lower()

        pattern_hits = []
        for pattern, atype in self._compiled_injection:
            if pattern.search(output_lower):
                pattern_hits.append(atype)

        score = 0.0
        if pattern_hits:
            score += 0.4 * len(pattern_hits)

        url_count = len(re.findall(r"https?://[^\s]+", agent_output))
        if url_count > 0:
            score += 0.1 * url_count

        code_blocks = len(re.findall(r"```[\s\S]*?```", agent_output))
        if code_blocks > 0 and any(t in ("code_execution", "terminal_injection") for t in pattern_hits):
            score += 0.2

        detected = score >= 0.4
        return {
            "detected": detected,
            "score": min(1.0, score),
            "type": pattern_hits[0] if pattern_hits else None,
            "hits": pattern_hits,
            "url_count": url_count,
            "code_block_count": code_blocks,
        }

    def _check_dlp_output(self, agent_output: str) -> Dict[str, Any]:
        from app.security.dlp import DLPEngine

        dlp = DLPEngine()
        dlp_result = dlp.check(agent_output)

        leak_types = []
        masked_text = agent_output
        for stype, pattern in self._compiled_sensitive.items():
            matches = pattern.findall(agent_output)
            if matches:
                leak_types.append(stype)
                for m in matches:
                    if isinstance(m, str):
                        masked_text = masked_text.replace(m, m[:4] + "****" + m[-4:] if len(m) > 8 else "****")

        score = dlp_result.get("score", 0.0)
        if leak_types:
            score = min(1.0, score + 0.2 * len(leak_types))

        leaked = score >= 0.4 or len(leak_types) > 0
        return {
            "leaked": leaked,
            "score": min(1.0, score),
            "leak_types": leak_types,
            "dlp_reasons": dlp_result.get("reasons", []),
            "masked_text": masked_text,
            "level": dlp_result.get("level", "low"),
        }

    def _detect_intent(self, text: str) -> str:
        scores = {}
        for intent, keywords in _INTENT_KEYWORDS.items():
            scores[intent] = sum(1 for kw in keywords if kw in text)
        if not scores:
            return "general"
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "general"

    def _compute_semantic_drift(self, text_a: str, text_b: str) -> float:
        tokens_a = self._tokenize(text_a)
        tokens_b = self._tokenize(text_b)
        if not tokens_a or not tokens_b:
            return 0.0

        counter_a = Counter(tokens_a)
        counter_b = Counter(tokens_b)

        all_tokens = set(tokens_a) | set(tokens_b)
        vec_a = [counter_a.get(t, 0) for t in all_tokens]
        vec_b = [counter_b.get(t, 0) for t in all_tokens]

        dot = sum(a * b for a, b in zip(vec_a, vec_b))
        mag_a = math.sqrt(sum(a * a for a in vec_a))
        mag_b = math.sqrt(sum(b * b for b in vec_b))

        if mag_a == 0 or mag_b == 0:
            return 1.0

        similarity = dot / (mag_a * mag_b)
        drift = 1.0 - similarity
        return min(1.0, max(0.0, drift))

    def _tokenize(self, text: str) -> List[str]:
        tokens = re.findall(r"[a-zA-Z]+|\d+|[\u4e00-\u9fff]", text.lower())
        return tokens

    def _compute_risk(
        self,
        hijack: Dict[str, Any],
        injection: Dict[str, Any],
        dlp: Dict[str, Any],
    ) -> float:
        h_score = hijack.get("score", 0.0) * 0.40
        i_score = injection.get("score", 0.0) * 0.35
        d_score = dlp.get("score", 0.0) * 0.25

        combined = h_score + i_score + d_score

        if hijack.get("detected") and injection.get("detected"):
            combined = min(1.0, combined * 1.3)

        return round(min(1.0, combined), 4)


_engine_instance: Optional[AlignmentCheckEngine] = None


def get_alignment_engine() -> AlignmentCheckEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = AlignmentCheckEngine()
    return _engine_instance


def check_alignment(
    original_message: str,
    agent_output: str,
    context: Optional[Dict[str, Any]] = None,
) -> AlignmentResult:
    engine = get_alignment_engine()
    return engine.check(original_message, agent_output, context)
