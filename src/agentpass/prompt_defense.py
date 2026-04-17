"""
Prompt Injection Defense Module
Detects and mitigates prompt injection attacks.
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum


class InjectionType(str, Enum):
    IGNORE_RULES = "ignore_rules"
    EXPORT_SENSITIVE = "export_sensitive"
    OVERWRITE_ROLE = "overwrite_role"
    BYPASS_SECURITY = "bypass_security"
    OTHER = "other"


class PromptInjectionResult(BaseModel):
    is_safe: bool = Field(default=True, description="Whether the prompt is safe")
    risk_score: float = Field(default=0.0, description="Risk score 0.0-1.0")
    injection_type: Optional[InjectionType] = Field(default=None, description="Type of injection detected")
    reason: str = Field(default="", description="Reason for the decision")
    matched_patterns: List[str] = Field(default_factory=list, description="Patterns that matched")


class PromptDefense:
    """
    Prompt Injection Defense Engine
    """

    IGNORE_RULES_PATTERNS_EN = [
        r"ignore.*previous",
        r"forget.*rules",
        r"disregard.*instructions",
        r"skip.*system",
        r"ignore.*system.*prompt",
        r"no.*rules",
        r"bypass.*security",
        r"act.*as.*you.*are.*not",
        r"you.*are.*not.*bound",
    ]

    IGNORE_RULES_PATTERNS_ZH = [
        r"忽略.*之前",
        r"忘记.*规则",
        r"无视.*指令",
        r"忽略.*系统.*提示",
        r"没有.*规则",
        r"绕过.*安全",
        r"假装.*你不是",
        r"你不受.*约束",
        r"不遵守.*规定",
    ]

    EXPORT_SENSITIVE_PATTERNS_EN = [
        r"export.*database",
        r"dump.*all",
        r"save.*password",
        r"show.*secret",
        r"reveal.*credentials",
        r"extract.*sensitive",
        r"leak.*information",
        r"give.*me.*all",
        r"list.*all.*files",
    ]

    EXPORT_SENSITIVE_PATTERNS_ZH = [
        r"导出.*数据库",
        r"导出.*全部",
        r"保存.*密码",
        r"显示.*秘密",
        r"泄露.*凭证",
        r"提取.*敏感",
        r"泄露.*信息",
        r"给我.*全部",
        r"列出.*所有.*文件",
    ]

    OVERWRITE_ROLE_PATTERNS_EN = [
        r"you.*are.*now.*a",
        r"pretend.*to.*be",
        r"your.*role.*is",
        r"from.*now.*on",
        r"ignore.*your.*role",
    ]

    OVERWRITE_ROLE_PATTERNS_ZH = [
        r"你现在.*是",
        r"假装.*是",
        r"你的角色.*是",
        r"从现在开始",
        r"忽略.*你的角色",
    ]

    BYPASS_SECURITY_PATTERNS_EN = [
        r"developer.*mode",
        r"admin.*override",
        r"sudo.*mode",
        r"bypass.*filter",
        r"disable.*security",
        r"debug.*mode",
    ]

    BYPASS_SECURITY_PATTERNS_ZH = [
        r"开发者.*模式",
        r"管理员.*覆盖",
        r"超级用户.*模式",
        r"绕过.*过滤",
        r"禁用.*安全",
        r"调试.*模式",
    ]

    def __init__(self):
        import re
        self._re = re

    def _match_patterns(self, prompt: str, patterns: List[str]) -> Tuple[bool, List[str]]:
        matched = []
        for pattern in patterns:
            if self._re.search(pattern, prompt, self._re.IGNORECASE):
                matched.append(pattern)
        return (len(matched) > 0, matched)

    def analyze(self, prompt: str) -> PromptInjectionResult:
        """
        Analyze a prompt for injection attacks.

        Args:
            prompt: The prompt text to analyze

        Returns:
            PromptInjectionResult with risk assessment
        """
        if not prompt or len(prompt.strip()) == 0:
            return PromptInjectionResult(is_safe=True, risk_score=0.0, reason="Empty prompt")

        is_safe = True
        risk_score = 0.0
        injection_type = None
        reason = ""
        matched_patterns = []

        # Check for ignore rules
        ignore_en, matched_ignore_en = self._match_patterns(prompt, self.IGNORE_RULES_PATTERNS_EN)
        ignore_zh, matched_ignore_zh = self._match_patterns(prompt, self.IGNORE_RULES_PATTERNS_ZH)

        if ignore_en or ignore_zh:
            is_safe = False
            risk_score = 0.9
            injection_type = InjectionType.IGNORE_RULES
            reason = "Prompt injection detected (ignore rules)"
            matched_patterns.extend(matched_ignore_en + matched_ignore_zh)

        # Check for export sensitive
        if is_safe:
            export_en, matched_export_en = self._match_patterns(prompt, self.EXPORT_SENSITIVE_PATTERNS_EN)
            export_zh, matched_export_zh = self._match_patterns(prompt, self.EXPORT_SENSITIVE_PATTERNS_ZH)

            if export_en or export_zh:
                is_safe = False
                risk_score = 0.95
                injection_type = InjectionType.EXPORT_SENSITIVE
                reason = "Sensitive data export request detected"
                matched_patterns.extend(matched_export_en + matched_export_zh)

        # Check for overwrite role
        if is_safe:
            role_en, matched_role_en = self._match_patterns(prompt, self.OVERWRITE_ROLE_PATTERNS_EN)
            role_zh, matched_role_zh = self._match_patterns(prompt, self.OVERWRITE_ROLE_PATTERNS_ZH)

            if role_en or role_zh:
                is_safe = False
                risk_score = 0.7
                injection_type = InjectionType.OVERWRITE_ROLE
                reason = "Role overwrite attempt detected"
                matched_patterns.extend(matched_role_en + matched_role_zh)

        # Check for bypass security
        if is_safe:
            bypass_en, matched_bypass_en = self._match_patterns(prompt, self.BYPASS_SECURITY_PATTERNS_EN)
            bypass_zh, matched_bypass_zh = self._match_patterns(prompt, self.BYPASS_SECURITY_PATTERNS_ZH)

            if bypass_en or bypass_zh:
                is_safe = False
                risk_score = 0.85
                injection_type = InjectionType.BYPASS_SECURITY
                reason = "Security bypass attempt detected"
                matched_patterns.extend(matched_bypass_en + matched_bypass_zh)

        return PromptInjectionResult(
            is_safe=is_safe,
            risk_score=risk_score,
            injection_type=injection_type,
            reason=reason,
            matched_patterns=matched_patterns
        )
