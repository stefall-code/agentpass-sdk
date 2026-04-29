import re
from typing import Dict, List, Tuple, Optional


class DLPEngine:
    """强 DLP 引擎"""
    
    # 敏感信息正则模式
    SENSITIVE_PATTERNS = {
        "phone": r"1[3-9]\d{9}",
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "id_card": r"[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]",
        "bank_card": r"[3-9]\d{12,18}",
        "api_key": r"api[_-]?key[_-]?[a-zA-Z0-9]{20,}",
        "access_token": r"access[_-]?token[_-]?[a-zA-Z0-9]{20,}",
        "jwt": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "github_token": r"gh[pousr]_[0-9a-zA-Z]{36}",
        "openai_key": r"sk-[a-zA-Z0-9]{48}",
        "db_connection": r"(mysql|postgresql|mongodb|redis):\/\/[^\s]+"
    }
    
    # 企业敏感关键词
    CORPORATE_SENSITIVE_KEYWORDS = {
        "confidential", "internal only", "salary", "payroll", 
        "customer list", "contract", "invoice", "source code", 
        "secret", "credentials", "财务报表", "客户名单", 
        "工资表", "内部资料", "合同", "发票", "密钥"
    }
    
    # 语义泄露意图模式
    SEMANTIC_LEAK_PATTERNS = {
        "export_data": [r"导出全部客户数据", r"给我数据库内容", r"打包内部文档", 
                      r"列出员工工资", r"输出管理员密码", r"发给外部邮箱", 
                      r"下载全部合同", r"export all customer data", 
                      r"give me database content", r"download all contracts"],
        "data_exfiltration": [r"发送到外部", r"保存到外部", r"share with external", 
                             r"send to external", r"save externally"]
    }
    
    def __init__(self):
        self._compiled_patterns = {}
        for name, pattern in self.SENSITIVE_PATTERNS.items():
            self._compiled_patterns[name] = re.compile(pattern, re.IGNORECASE)
    
    def check(self, text: str) -> Dict:
        """检查文本中的敏感信息"""
        if not text:
            return {
                "score": 0.0,
                "level": "low",
                "blocked": False,
                "reasons": [],
                "masked_text": text
            }
        
        score = 0.0
        reasons = []
        masked_text = text
        
        # 1. 敏感信息识别
        sensitive_matches = self._detect_sensitive_info(text)
        for info_type, matches in sensitive_matches.items():
            if matches:
                count = len(matches)
                score += 0.2 * count
                reasons.append(f"检测到 {info_type} (数量: {count})")
                # 脱敏处理
                for match in matches:
                    masked_text = self._mask_sensitive_info(info_type, match, masked_text)
        
        # 2. 企业敏感数据识别
        corporate_matches = self._detect_corporate_sensitive(text)
        if corporate_matches:
            score += 0.3 * len(corporate_matches)
            reasons.extend([f"检测到企业敏感关键词: {keyword}" for keyword in corporate_matches])
        
        # 3. 语义泄露识别
        semantic_matches = self._detect_semantic_leak(text)
        if semantic_matches:
            score += 0.5 * len(semantic_matches)
            reasons.extend([f"检测到语义泄露意图: {intent}" for intent in semantic_matches])
        
        # 计算风险等级
        level = self._calculate_risk_level(score)
        blocked = score > 0.7
        
        return {
            "score": min(1.0, score),
            "level": level,
            "blocked": blocked,
            "reasons": reasons,
            "masked_text": masked_text
        }
    
    def _detect_sensitive_info(self, text: str) -> Dict[str, List[str]]:
        """检测敏感信息"""
        matches = {}
        for info_type, pattern in self._compiled_patterns.items():
            found = pattern.findall(text)
            if found:
                # 处理捕获组返回元组的情况
                if found and isinstance(found[0], tuple):
                    # 对于有捕获组的正则，使用 search 来获取完整匹配
                    actual_matches = []
                    for match in pattern.finditer(text):
                        actual_matches.append(match.group(0))
                    matches[info_type] = actual_matches
                else:
                    matches[info_type] = found
        return matches
    
    def _detect_corporate_sensitive(self, text: str) -> List[str]:
        """检测企业敏感关键词"""
        found = []
        text_lower = text.lower()
        for keyword in self.CORPORATE_SENSITIVE_KEYWORDS:
            if keyword.lower() in text_lower:
                found.append(keyword)
        return found
    
    def _detect_semantic_leak(self, text: str) -> List[str]:
        """检测语义泄露意图"""
        found = []
        text_lower = text.lower()
        for intent, patterns in self.SEMANTIC_LEAK_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    found.append(intent)
                    break
        return found
    
    def _mask_sensitive_info(self, info_type: str, match: str, text: str) -> str:
        """脱敏敏感信息"""
        if info_type == "phone":
            return text.replace(match, f"{match[:3]}****{match[-4:]}")
        elif info_type == "id_card":
            return text.replace(match, f"{match[:6]}********{match[-4:]}")
        elif info_type == "bank_card":
            return text.replace(match, f"{match[:4]} **** **** {match[-4:]}")
        elif info_type in ["api_key", "access_token", "jwt", "aws_key", "github_token", "openai_key"]:
            return text.replace(match, f"{match[:4]}****{match[-4:]}")
        elif info_type == "email":
            parts = match.split('@')
            if len(parts) == 2:
                username, domain = parts
                masked_username = username[:2] + "*" * (len(username) - 2) if len(username) > 2 else username
                return text.replace(match, f"{masked_username}@{domain}")
        return text
    
    def _calculate_risk_level(self, score: float) -> str:
        """计算风险等级"""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"
