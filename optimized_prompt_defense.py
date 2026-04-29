#!/usr/bin/env python3
"""
优化版提示词防御系统
基于10000样本测试结果进行改进
"""
import re
import unicodedata
from typing import Dict, List, Optional, Tuple
from collections import Counter, deque
from enum import Enum
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / "agentpass-sdk" / "src"))


class InjectionType(str, Enum):
    IGNORE_RULES = "ignore_rules"
    EXPORT_SENSITIVE = "export_sensitive"
    OVERWRITE_ROLE = "overwrite_role"
    BYPASS_SECURITY = "bypass_security"
    JAILBREAK_ROLEPLAY = "jailbreak_roleplay"
    INDIRECT_INJECTION = "indirect_injection"
    TOKEN_SMUGGLING = "token_smuggling"
    GOAL_HIJACKING = "goal_hijacking"
    PROMPT_LEAKING = "prompt_leaking"
    OTHER = "other"


# 通用前缀和后缀词 - 这些词经常被添加在攻击提示词前后
NOISE_WORDS = [
    "请", "麻烦你", "帮我", "我需要你", "谢谢", "尽快", "急", "在线等", "麻烦了",
    "please", "could you", "help me", "i need you", "thank you", "thanks", "asap",
]


class OptimizedPromptDefense:
    """优化版提示词防御"""
    
    # === 增强的攻击模式（包括更多变体 ===
    IGNORE_RULES_PATTERNS = [
        r"ignore.*previous", r"forget.*rules", r"disregard.*instructions",
        r"skip.*system", r"ignore.*system.*prompt", r"no.*rules",
        r"act.*as.*you.*are.*not", r"you.*are.*not.*bound",
        r"忽略.*之前", r"忘记.*规则", r"无视.*指令",
        r"忽略.*系统.*提示", r"不遵守.*规定", r"忽略.*规定",
        r"不要.*遵守", r"不受.*限制", r"不需要.*规则",
        r"取消.*限制", r"解除.*限制", r"忽略所有规则",
    ]
    
    EXPORT_SENSITIVE_PATTERNS = [
        r"export.*database", r"dump.*all", r"save.*password",
        r"show.*secret", r"reveal.*credentials", r"extract.*sensitive",
        r"leak.*information", r"give.*me.*all", r"list.*all.*files",
        r"download.*all.*data", r"get.*all.*password", r"access.*all.*records",
        r"dump.*credentials", r"expose.*secrets", r"steal.*password",
        r"steal.*data", r"export.*all",
        r"导出.*数据库", r"导出.*全部", r"保存.*密码",
        r"导出.*敏感.*数据", r"导出.*财务.*数据",
        r"导出.*用户.*密码", r"获取.*所有.*密码",
        r"导出.*CSV", r"整理成.*CSV", r"发送到.*邮箱",
        r"发送.*外部", r"导出.*所有.*密码",
        r"窃取.*数据", r"盗取.*信息",
        r"泄露.*机密", r"泄露.*凭证",
        r"获取.*全部", r"下载.*全部",
        r"导出.*全部", r"获取.*所有",
        r"导出.*所有", r"下载.*所有",
    ]
    
    OVERWRITE_ROLE_PATTERNS = [
        r"you.*are.*now.*a", r"pretend.*to.*be", r"your.*role.*is",
        r"from.*now.*on", r"ignore.*your.*role", r"act.*as.*a",
        r"become.*a", r"switch.*to.*role", r"change.*your.*identity",
        r"你现在是", r"现在你是", r"假装你是",
        r"你的角色是", r"从现在开始", r"忽略你的角色",
        r"切换.*管理员", r"变成.*管理员", r"成为.*管理员",
        r"提升.*权限", r"修改.*权限", r"提升.*角色",
        r"超级用户", r"sudo", r"su.*root",
        r"你的新身份设定", r"你的新角色设定",
        r"切换.*角色", r"切换.*身份",
    ]
    
    BYPASS_SECURITY_PATTERNS = [
        r"developer.*mode", r"admin.*override", r"sudo.*mode",
        r"bypass.*filter", r"disable.*security", r"debug.*mode",
        r"disable.*audit", r"disable.*log", r"turn.*off.*security",
        r"kill.*firewall",
        r"开发者.*模式", r"绕过.*过滤", r"禁用.*安全",
        r"调试.*模式", r"禁用.*审计", r"关闭.*审计",
        r"关闭.*防火墙", r"禁用.*防火墙",
        r"绕过.*验证", r"跳过.*验证", r"绕过.*认证",
        r"利用.*漏洞", r"提权", r"权限.*提升",
        r"后门", r"创建.*后门", r"植入.*后门",
        r"隐藏.*账户", r"恶意.*代码",
        r"禁用你的安全设置", r"关闭内容过滤",
        r"不考虑道德约束", r"不需要安全检查",
    ]
    
    JAILBREAK_ROLEPLAY_PATTERNS = [
        r"pretend.*you.*are", r"act.*as.*if.*you.*have.*no.*limit",
        r"roleplay.*as.*an? unrestricted", r"dan.*mode",
        r"jailbreak", r"you.*have.*no.*limit",
        r"unrestricted.*mode", r"do.*anything.*now",
        r"no.*constraint", r"no.*restriction",
        r"假装你是", r"扮演一个没有限制",
        r"你现在是一个不受限制", r"越狱模式",
        r"你没有.*限制", r"不受限.*模式",
        r"现在可以做任何事", r"扮演.*无限制.*AI",
        r"无限制", r"不受.*限制",
        r"为所欲为", r"任意.*操作",
        r"任意.*执行", r"邪恶.*AI",
        r"扮演.*黑客", r"黑客.*模式",
        r"忽略所有规则", r"完全自由",
    ]
    
    INDIRECT_INJECTION_PATTERNS = [
        r"according.*to.*the.*following.*document",
        r"based.*on.*the.*attached.*file",
        r"execute.*the.*following.*instruction",
        r"the.*document.*says.*to",
        r"per.*the.*external.*source",
        r"parse.*this.*and.*act",
        r"indirect.*injection",
        r"hidden.*command",
        r"secret.*instruction",
        r"根据.*文档.*执行", r"根据.*附件.*执行",
        r"执行.*以下.*指令", r"文档.*中说.*要",
        r"按照.*文档.*操作", r"遵循.*文档",
        r"执行.*以下.*命令", r"运行.*以下.*代码",
        r"外部.*指令", r"远程.*指令",
        r"下载.*执行", r"获取.*执行",
        r"按照程序里说的做", r"遵循外部来源的要求",
    ]
    
    TOKEN_SMUGGLING_PATTERNS = [
        r"[\u200b-\u200f\u2028-\u202f\ufeff]",
        r"[\x00-\x08\x0b\x0c\x0e-\x1f]",
        r"\\x[0-9a-fA-F]{2}",
        r"\\u[0-9a-fA-F]{4}",
        r"[a-zA-Z0-9+/=]{20,}",
        r"rot13", r"decode.*thi", r"obfuscat",
        r"隐藏.*指令", r"零宽", r"零宽字符",
        r"混淆.*指令", r"解密.*执行",
        r"token.*走私", r"走私.*token",
    ]
    
    GOAL_HIJACKING_PATTERNS = [
        r"(帮我|请先|请)?(顺便|同时|另外|also|meanwhile|additionally).*(删除|导出|绕过|发送|上传|delete|export|bypass|send|upload)",
    ]
    
    PROMPT_LEAKING_PATTERNS = [
        r"(重复|输出|显示|打印|复述|repeat|output|show|print|echo).*(系统.*提示|初始.*指令|原始.*规则|prompt|system prompt|initial instruction)",
    ]
    
    def __init__(self, threshold: float = 0.28):
        """初始化，可自定义阈值"""
        self.threshold = threshold
        self._compiled = {}
        self._dialog_history = {}
        
        self._RULE_GROUPS = [
            (InjectionType.IGNORE_RULES, self.IGNORE_RULES_PATTERNS),
            (InjectionType.EXPORT_SENSITIVE, self.EXPORT_SENSITIVE_PATTERNS),
            (InjectionType.OVERWRITE_ROLE, self.OVERWRITE_ROLE_PATTERNS),
            (InjectionType.BYPASS_SECURITY, self.BYPASS_SECURITY_PATTERNS),
            (InjectionType.JAILBREAK_ROLEPLAY, self.JAILBREAK_ROLEPLAY_PATTERNS),
            (InjectionType.INDIRECT_INJECTION, self.INDIRECT_INJECTION_PATTERNS),
            (InjectionType.TOKEN_SMUGGLING, self.TOKEN_SMUGGLING_PATTERNS),
            (InjectionType.GOAL_HIJACKING, self.GOAL_HIJACKING_PATTERNS),
            (InjectionType.PROMPT_LEAKING, self.PROMPT_LEAKING_PATTERNS),
        ]
        
        for _, patterns in self._RULE_GROUPS:
            for p in patterns:
                if p not in self._compiled:
                    self._compiled[p] = re.compile(p, re.IGNORECASE | re.UNICODE)
    
    def _preprocess_prompt(self, prompt: str) -> str:
        """预处理提示词 - 移降噪词和进行规范化"""
        prompt = prompt.strip()
        prompt = unicodedata.normalize("NFKC", prompt)
        
        # 移除常见前缀后缀
        for noise in NOISE_WORDS:
            pattern = r'^\s*' + re.escape(noise) + r'\s*'
            prompt = re.sub(pattern, '', prompt, flags=re.IGNORECASE)
            pattern = r'\s*' + re.escape(noise) + r'\s*$'
            prompt = re.sub(pattern, '', prompt, flags=re.IGNORECASE)
        
        return prompt.strip()
    
    def _match_patterns(self, prompt: str, patterns: List[str]) -> Tuple[bool, List[str]]:
        """匹配模式，支持预处理后的匹配"""
        matched = []
        # 原始提示词
        original_prompt = prompt
        # 预处理后的提示词
        processed_prompt = self._preprocess_prompt(prompt)
        
        for p in patterns:
            if p in self._compiled:
                if self._compiled[p].search(original_prompt):
                    matched.append(p)
                elif self._compiled[p].search(processed_prompt):
                    matched.append(p)
        
        return len(matched) > 0, matched
    
    def analyze(self, prompt: str) -> Dict:
        """分析提示词"""
        if not prompt or not prompt.strip():
            return {
                "is_safe": True,
                "risk_score": 0.0,
                "reason": "Empty prompt"
            }
        
        all_triggered = []
        all_matched = []
        primary_type = None
        max_score = 0.0
        
        # 第一层：规则匹配
        for attack_type, patterns in self._RULE_GROUPS:
            hit, matched = self._match_patterns(prompt, patterns)
            if hit:
                raw_score = min(1.0, 0.4 + len(matched) * 0.2)
                all_triggered.append({
                    "type": attack_type,
                    "score": raw_score,
                    "matched": matched
                })
                all_matched.extend(matched)
                if raw_score > max_score:
                    max_score = raw_score
                    primary_type = attack_type
        
        # 计算最终风险分数
        if all_triggered:
            rule_score = sum(t["score"] for t in all_triggered) / len(all_triggered)
            # 增强系数：触发多个规则时提高分数
            if len(all_triggered) > 1:
                rule_score = min(1.0, rule_score * 1.2)
        else:
            rule_score = 0.0
        
        # Token走私检测单独提升风险
        token_smuggling = self._detect_token_smuggling(prompt)
        if token_smuggling:
            rule_score = max(rule_score, 0.85)
        
        final_score = rule_score
        is_safe = final_score < self.threshold
        
        reason_parts = []
        if all_triggered:
            reason_parts.append(f"规则层({rule_score:.2f})")
        if token_smuggling:
            reason_parts.append("Token走私")
        reason = "；".join(reason_parts) if reason_parts else "未检测到异常"
        
        return {
            "is_safe": is_safe,
            "risk_score": round(final_score, 4),
            "injection_type": primary_type.value if primary_type else None,
            "reason": reason,
            "matched_patterns": all_matched,
            "token_smuggling": token_smuggling,
        }
    
    def _detect_token_smuggling(self, prompt: str) -> bool:
        """检测Token走私"""
        zwc = re.search(r"[\u200b-\u200f\u2028-\u202f\ufeff]", prompt)
        if zwc:
            return True
        escape_seq = re.search(r"(?:\\x[0-9a-fA-F]{2}){2,}", prompt)
        if escape_seq:
            return True
        escape_u = re.search(r"(?:\\u[0-9a-fA-F]{4}){2,}", prompt)
        if escape_u:
            return True
        b64_in_text = re.search(r"[a-zA-Z0-9+/=]{20,}", prompt)
        if b64_in_text:
            return True
        return False


def test_optimized_version():
    """测试优化版"""
    import json
    from collections import defaultdict, Counter
    
    print("="*80)
    print("优化版提示词防御测试")
    print("="*80)
    
    # 加载之前生成的测试结果
    with open("prompt_defense_results.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # 提取原始数据集（从结果中重建）
    dataset = []
    for r in data["results"]:
        dataset.append({
            "prompt": r["prompt"],
            "true_label": r["true_label"],
            "true_type": r["true_type"],
        })
    
    # 测试不同阈值
    thresholds = [0.25, 0.28, 0.30, 0.32, 0.35]
    
    best_threshold = None
    best_f1 = 0
    
    for threshold in thresholds:
        print(f"\n测试阈值: {threshold}")
        defense = OptimizedPromptDefense(threshold=threshold)
        
        tp = fp = tn = fn = 0
        
        for sample in dataset:
            result = defense.analyze(sample["prompt"])
            is_attack_true = sample["true_label"] == "attack"
            is_attack_pred = not result["is_safe"]
            
            if is_attack_true:
                if is_attack_pred:
                    tp += 1
                else:
                    fn += 1
            else:
                if is_attack_pred:
                    fp += 1
                else:
                    tn += 1
        
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"  准确率: {accuracy*100:.2f}%")
        print(f"  精确率: {precision*100:.2f}%")
        print(f"  召回率: {recall*100:.2f}%")
        print(f"  F1: {f1*100:.2f}%")
        print(f"  TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
    
    print(f"\n最佳阈值: {best_threshold}, F1分数: {best_f1*100:.2f}%")
    
    # 使用最佳阈值重新测试并保存详细结果
    print(f"\n使用最佳阈值 {best_threshold} 进行详细分析...")
    defense = OptimizedPromptDefense(threshold=best_threshold)
    
    tp = fp = tn = fn = 0
    attack_type_stats = defaultdict(lambda: {"tp": 0, "fn": 0, "total": 0})
    
    for sample in dataset:
        result = defense.analyze(sample["prompt"])
        is_attack_true = sample["true_label"] == "attack"
        is_attack_pred = not result["is_safe"]
        
        if is_attack_true:
            attack_type = sample["true_type"] or "unknown"
            attack_type_stats[attack_type]["total"] += 1
            if is_attack_pred:
                tp += 1
                attack_type_stats[attack_type]["tp"] += 1
            else:
                fn += 1
                attack_type_stats[attack_type]["fn"] += 1
        else:
            if is_attack_pred:
                fp += 1
            else:
                tn += 1
    
    print(f"\n【详细结果】")
    print(f"  准确率: {(tp+tn)/(tp+tn+fp+fn)*100:.2f}%")
    precision = tp/(tp+fp) if (tp+fp) > 0 else 0
    recall = tp/(tp+fn) if (tp+fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    print(f"  精确率: {precision*100:.2f}%")
    print(f"  召回率: {recall*100:.2f}%")
    print(f"  F1: {f1*100:.2f}%")
    print(f"\n【各攻击类型召回率】")
    for attack_type, stats in attack_type_stats.items():
        if attack_type == "false_alarm":
            continue
        recall = stats["tp"] / stats["total"] if stats["total"] > 0 else 0
        print(f"  {attack_type:20s}: {recall*100:5.2f}% (TP: {stats['tp']}, FN: {stats['fn']}, 总数: {stats['total']})")


if __name__ == "__main__":
    test_optimized_version()
