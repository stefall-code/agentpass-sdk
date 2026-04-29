"""
P2 Engineering Upgrade API Router — Ed25519 / Declarative Policy / SIEM / NL Translator
"""
from __future__ import annotations

import sys
from typing import Dict, Any, List, Optional
from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.security.ed25519_auth import (
    generate_keypair, register_public_key, issue_challenge, verify_challenge_response,
    sign_challenge_locally, get_ed25519_status, get_agent_auth_info,
)
from app.security.declarative_policy import (
    load_policy_from_dict, load_policy_from_json, evaluate_policy,
    list_policies, get_policy, delete_policy, toggle_policy, get_policy_engine_status,
)
from app.security.siem_integration import (
    emit_siem_event, export_splunk, export_elk, export_datadog,
    start_otel_span, add_otel_span_event, end_otel_span, export_otel_traces,
    generate_soc2_report, generate_hipaa_report, get_siem_status,
)
from app.security.nl_translator import (
    translate_nl_to_acl, confirm_rule, reject_rule, list_nl_rules, get_nl_translator_status,
)
from app.security.agentpass_architecture import (
    get_architecture, get_core_innovation_demo, get_system_status,
)
from app.security.six_layer_verify import (
    verify_six_layers, get_verification_history, get_live_attack_demo,
)
from app.security.judge_verify import (
    run_full_judge_verification,
    verify_a2a_token_schema, verify_chain_unforgeable,
    verify_prompt_defense_is_iam, verify_no_api_bypass,
    verify_external_agent_attack, verify_three_failure_strategies,
    verify_honest_capability_framing,
)
from app.security.standard_hitl import (
    get_standard_alignment, get_hitl_config, get_killer_summary,
    submit_hitl_review, decide_hitl_review, get_hitl_queue,
)

router = APIRouter(prefix="/p2", tags=["P2 Engineering Upgrade"])


class GenerateKeypairRequest(BaseModel):
    agent_id: str


class RegisterPubKeyRequest(BaseModel):
    agent_id: str
    public_key_b64: str


class ChallengeRequest(BaseModel):
    agent_id: str


class VerifyChallengeRequest(BaseModel):
    challenge_id: str
    signature_b64: str
    agent_id: str


class SignLocalRequest(BaseModel):
    private_key_b64: str
    challenge_b64: str


class LoadPolicyRequest(BaseModel):
    policy_json: str = Field(default="", description="JSON policy string")
    policy_data: Optional[Dict[str, Any]] = Field(default=None, description="Policy dict")


class EvaluatePolicyRequest(BaseModel):
    agent_id: str
    action: str
    context: Optional[Dict[str, Any]] = None


class TogglePolicyRequest(BaseModel):
    name: str
    enabled: bool


class DeletePolicyRequest(BaseModel):
    name: str


class EmitSIEMEventRequest(BaseModel):
    event_type: str
    agent_id: str
    action: str = ""
    resource: str = ""
    decision: str = ""
    reason: str = ""
    severity: str = "info"


class OtelSpanRequest(BaseModel):
    trace_id: str
    span_name: str
    agent_id: str
    parent_span_id: Optional[str] = None


class OtelSpanEventRequest(BaseModel):
    span_id: str
    event_name: str
    attributes: Optional[Dict[str, Any]] = None


class EndOtelSpanRequest(BaseModel):
    span_id: str
    status: str = "OK"


class NLTranslateRequest(BaseModel):
    text: str
    agent_id: str = ""


class ConfirmRuleRequest(BaseModel):
    rule_id: str


class RejectRuleRequest(BaseModel):
    rule_id: str


# === Ed25519 Endpoints ===

@router.post("/ed25519/generate-keypair")
async def generate_keypair_endpoint(req: GenerateKeypairRequest):
    return generate_keypair(req.agent_id)


@router.post("/ed25519/register-public-key")
async def register_pubkey_endpoint(req: RegisterPubKeyRequest):
    return register_public_key(req.agent_id, req.public_key_b64)


@router.post("/ed25519/issue-challenge")
async def issue_challenge_endpoint(req: ChallengeRequest):
    return issue_challenge(req.agent_id)


@router.post("/ed25519/verify-response")
async def verify_response_endpoint(req: VerifyChallengeRequest):
    return verify_challenge_response(req.challenge_id, req.signature_b64, req.agent_id)


@router.post("/ed25519/sign-locally")
async def sign_locally_endpoint(req: SignLocalRequest):
    sig = sign_challenge_locally(req.private_key_b64, req.challenge_b64)
    return {"signature_b64": sig}


@router.get("/ed25519/status")
async def ed25519_status_endpoint():
    return get_ed25519_status()


@router.get("/ed25519/agent/{agent_id}")
async def agent_auth_info_endpoint(agent_id: str):
    return get_agent_auth_info(agent_id)


# === Declarative Policy Endpoints ===

@router.post("/policy/load")
async def load_policy_endpoint(req: LoadPolicyRequest):
    if req.policy_data:
        return load_policy_from_dict(req.policy_data)
    if req.policy_json:
        return load_policy_from_json(req.policy_json)
    return {"loaded": False, "reason": "Provide policy_json or policy_data"}


@router.post("/policy/evaluate")
async def evaluate_policy_endpoint(req: EvaluatePolicyRequest):
    return evaluate_policy(req.agent_id, req.action, req.context)


@router.get("/policy/list")
async def list_policies_endpoint():
    return list_policies()


@router.get("/policy/{name}")
async def get_policy_endpoint(name: str):
    return get_policy(name)


@router.post("/policy/toggle")
async def toggle_policy_endpoint(req: TogglePolicyRequest):
    return toggle_policy(req.name, req.enabled)


@router.post("/policy/delete")
async def delete_policy_endpoint(req: DeletePolicyRequest):
    return delete_policy(req.name)


@router.get("/policy-engine/status")
async def policy_engine_status_endpoint():
    return get_policy_engine_status()


# === SIEM Endpoints ===

@router.post("/siem/emit")
async def emit_siem_endpoint(req: EmitSIEMEventRequest):
    return emit_siem_event(
        event_type=req.event_type,
        agent_id=req.agent_id,
        action=req.action,
        resource=req.resource,
        decision=req.decision,
        reason=req.reason,
        severity=req.severity,
    )


@router.get("/siem/export/splunk")
async def export_splunk_endpoint():
    return export_splunk()


@router.get("/siem/export/elk")
async def export_elk_endpoint():
    return export_elk()


@router.get("/siem/export/datadog")
async def export_datadog_endpoint():
    return export_datadog()


@router.post("/otel/start-span")
async def start_otel_span_endpoint(req: OtelSpanRequest):
    return start_otel_span(req.trace_id, req.span_name, req.agent_id, req.parent_span_id)


@router.post("/otel/span-event")
async def add_otel_span_event_endpoint(req: OtelSpanEventRequest):
    return add_otel_span_event(req.span_id, req.event_name, req.attributes)


@router.post("/otel/end-span")
async def end_otel_span_endpoint(req: EndOtelSpanRequest):
    return end_otel_span(req.span_id, req.status)


@router.get("/otel/traces")
async def otel_traces_endpoint():
    return export_otel_traces()


@router.get("/compliance/soc2")
async def soc2_report_endpoint():
    return generate_soc2_report()


@router.get("/compliance/hipaa")
async def hipaa_report_endpoint():
    return generate_hipaa_report()


@router.get("/siem/status")
async def siem_status_endpoint():
    return get_siem_status()


# === NL Translator Endpoints ===

@router.post("/nl/translate")
async def nl_translate_endpoint(req: NLTranslateRequest):
    return translate_nl_to_acl(req.text, req.agent_id)


@router.post("/nl/confirm-rule")
async def confirm_rule_endpoint(req: ConfirmRuleRequest):
    return confirm_rule(req.rule_id)


@router.post("/nl/reject-rule")
async def reject_rule_endpoint(req: RejectRuleRequest):
    return reject_rule(req.rule_id)


@router.get("/nl/rules")
async def nl_rules_endpoint():
    return list_nl_rules()


@router.get("/nl/status")
async def nl_status_endpoint():
    return get_nl_translator_status()


# === P2 Full Demo ===

@router.post("/demo")
async def p2_demo():
    steps = []

    # === P2-7: Ed25519 Challenge-Response ===
    kp = generate_keypair("secure_agent")
    steps.append({
        "step": 1,
        "action": "P2-7: Ed25519 密钥对生成",
        "feature": "Ed25519 Challenge-Response",
        "agent_id": "secure_agent",
        "fingerprint": kp["fingerprint"],
        "has_private_key": bool(kp["private_key_b64"]),
        "has_public_key": bool(kp["public_key_b64"]),
        "key_point": "Agent 本地生成 Ed25519 密钥对，私钥永远不离开 Agent，公钥注册到 Broker",
        "level": "ed25519_keygen",
    })

    register_result = register_public_key("secure_agent", kp["public_key_b64"])
    steps.append({
        "step": 2,
        "action": "P2-7: 公钥注册到 Broker",
        "feature": "Ed25519 Challenge-Response",
        "registered": register_result["registered"],
        "fingerprint": register_result.get("fingerprint", ""),
        "key_point": "只注册公钥到服务器，私钥保留在本地 — 防止 API Key 泄露和重放攻击",
        "level": "ed25519_register",
    })

    challenge = issue_challenge("secure_agent")
    steps.append({
        "step": 3,
        "action": "P2-7: Broker 发送随机挑战",
        "feature": "Ed25519 Challenge-Response",
        "challenge_id": challenge["challenge_id"],
        "challenge_preview": challenge["challenge"][:24] + "...",
        "expires_in": challenge["expires_in"],
        "key_point": "每次认证发送 32 字节随机挑战，5 分钟过期，防止重放攻击",
        "level": "ed25519_challenge",
    })

    signature = sign_challenge_locally(kp["private_key_b64"], challenge["challenge"])
    verify_result = verify_challenge_response(challenge["challenge_id"], signature, "secure_agent")
    steps.append({
        "step": 4,
        "action": "P2-7: Agent 签名 + Broker 验证",
        "feature": "Ed25519 Challenge-Response",
        "verified": verify_result["verified"],
        "session_token": verify_result.get("session_token", "")[:16] + "...",
        "key_point": "Agent 用私钥签名挑战，Broker 用公钥验证 — 零知识证明身份，私钥不传输",
        "level": "ed25519_verify",
    })

    fake_sig = base64_encode_fake()
    fake_verify = verify_challenge_response("fake_ch_id", fake_sig, "secure_agent")
    steps.append({
        "step": 5,
        "action": "P2-7: 伪造签名被拒绝",
        "feature": "Ed25519 Challenge-Response",
        "fake_verified": fake_verify["verified"],
        "fake_reason": fake_verify.get("reason", ""),
        "key_point": "伪造签名无法通过 Ed25519 验证 — 比 HMAC 比对安全得多",
        "level": "ed25519_fake",
    })

    # === P2-8: Declarative Policy ===
    finance_policy = {
        "name": "finance-data-access",
        "target": "data_agent",
        "version": "1.0",
        "priority": 60,
        "rules": [
            {"action": "read:feishu_table:finance", "condition": "trust_score >= 0.7 AND time.is_business_hours == true", "effect": "allow", "reason": "Trusted agents can read finance data during business hours"},
            {"action": "write:feishu_table:finance", "condition": "role == 'admin'", "effect": "deny", "reason": "Only admin can write finance data"},
            {"action": "export:feishu_table:finance", "condition": "trust_score >= 0.9 AND approval_status == 'approved'", "effect": "allow", "reason": "Export requires high trust + approval"},
        ],
    }
    load_result = load_policy_from_dict(finance_policy)
    steps.append({
        "step": 6,
        "action": "P2-8: 加载声明式策略（JSON/YAML）",
        "feature": "Declarative Policy",
        "policy_name": "finance-data-access",
        "rules_loaded": load_result.get("rules_count", 0),
        "key_point": "策略以声明式 JSON/YAML 定义，无需修改代码即可更新权限规则",
        "level": "policy_load",
    })

    eval1 = evaluate_policy("data_agent", "read:feishu_table:finance", {"trust_score": 0.8, "role": "operator"})
    eval2 = evaluate_policy("data_agent", "write:feishu_table:finance", {"trust_score": 0.9, "role": "operator"})
    steps.append({
        "step": 7,
        "action": "P2-8: 策略评估 — 条件表达式引擎",
        "feature": "Declarative Policy",
        "read_finance": {"decision": eval1["decision"], "reason": eval1.get("reason", "")[:50]},
        "write_finance": {"decision": eval2["decision"], "reason": eval2.get("reason", "")[:50]},
        "key_point": "trust_score>=0.7 + 工作时间 → 允许读取；role!=admin → 拒绝写入（deny-override）",
        "level": "policy_eval",
    })

    # === P2-9: SIEM Integration ===
    import uuid as _uuid
    trace_id = f"trace_{_uuid.uuid4().hex[:16]}"

    span1 = start_otel_span(trace_id, "agent_auth", "secure_agent")
    emit_siem_event("auth_success", "secure_agent", "login", "agent-iam", "allow", "Ed25519 verified", "info")
    add_otel_span_event(span1["span_id"], "auth_verified", {"method": "ed25519"})
    end_otel_span(span1["span_id"], "OK")

    span2 = start_otel_span(trace_id, "policy_check", "data_agent", parent_span_id=span1["span_id"])
    emit_siem_event("policy_deny", "data_agent", "write:feishu_table:finance", "finance_data", "deny", "Not admin role", "high")
    add_otel_span_event(span2["span_id"], "policy_evaluated", {"decision": "deny", "rule": "finance-data-access"})
    end_otel_span(span2["span_id"], "PERMISSION_DENIED")

    steps.append({
        "step": 8,
        "action": "P2-9: OpenTelemetry 分布式追踪",
        "feature": "SIEM Integration",
        "trace_id": trace_id,
        "spans": 2,
        "span1": {"name": "agent_auth", "status": "OK"},
        "span2": {"name": "policy_check", "status": "PERMISSION_DENIED", "parent": span1["span_id"][:16]},
        "key_point": "每个请求生成 Trace + Span，跨服务追踪 Agent 行为链路",
        "level": "siem_otel",
    })

    splunk_data = export_splunk()
    elk_data = export_elk()
    steps.append({
        "step": 9,
        "action": "P2-9: SIEM 日志导出（Splunk / ELK / Datadog）",
        "feature": "SIEM Integration",
        "splunk_events": len(splunk_data),
        "elk_events": len(elk_data),
        "export_formats": ["Splunk HEC JSON", "Elastic Common Schema", "Datadog Log API"],
        "key_point": "安全事件自动格式化为 Splunk/ELK/Datadog 格式，一键对接企业 SIEM",
        "level": "siem_export",
    })

    soc2 = generate_soc2_report()
    hipaa = generate_hipaa_report()
    steps.append({
        "step": 10,
        "action": "P2-9: 合规报告（SOC 2 / HIPAA）",
        "feature": "SIEM Integration",
        "soc2_criteria": len(soc2.get("trust_service_criteria", {})),
        "hipaa_safeguards": len(hipaa.get("safeguards", {})),
        "key_point": "自动生成 SOC 2 Type II 和 HIPAA 合规报告，满足审计要求",
        "level": "siem_compliance",
    })

    # === P2-10: NL Permission Translation ===
    nl1 = translate_nl_to_acl("只能读取财务数据，不能修改", "data_agent")
    steps.append({
        "step": 11,
        "action": "P2-10: 自然语言 → ACL 规则翻译",
        "feature": "NL Permission Translation",
        "input": "只能读取财务数据，不能修改",
        "rules_generated": len(nl1.get("rules", [])),
        "confidence": nl1.get("overall_confidence", 0),
        "key_point": "自然语言描述自动翻译为可审计的 ACL 规则，提取意图+资源+效果",
        "level": "nl_translate",
    })

    rule_summaries = []
    for r in nl1.get("rules", []):
        rule_summaries.append({"action": r["action"], "effect": r["effect"], "confidence": r["confidence"]})

    steps.append({
        "step": 12,
        "action": "P2-10: 提取的权限规则详情",
        "feature": "NL Permission Translation",
        "rules": rule_summaries,
        "extracted_intents": nl1.get("extracted_intents", []),
        "extracted_resources": nl1.get("extracted_resources", []),
        "extracted_effects": nl1.get("extracted_effects", {}),
        "scope": nl1.get("scope", ""),
        "key_point": "'只能读取'→ read:allow + write:deny，'财务数据'→ feishu_table:finance",
        "level": "nl_rules",
    })

    if nl1.get("rules"):
        first_rule_id = nl1["rules"][0]["rule_id"]
        confirm_result = confirm_rule(first_rule_id)
        steps.append({
            "step": 13,
            "action": "P2-10: 人工确认规则（HITL）",
            "feature": "NL Permission Translation",
            "confirmed": confirm_result.get("confirmed", False),
            "rule_id": first_rule_id,
            "key_point": "低置信度规则需人工确认后才生效 — Human-in-the-Loop 安全机制",
            "level": "nl_confirm",
        })

    nl2 = translate_nl_to_acl("在工作时间内，受信任的Agent可以导出HR数据，但需要审批", "hr_agent")
    steps.append({
        "step": 14,
        "action": "P2-10: 复杂自然语言翻译（条件+审批）",
        "feature": "NL Permission Translation",
        "input": "在工作时间内，受信任的Agent可以导出HR数据，但需要审批",
        "rules_generated": len(nl2.get("rules", [])),
        "extracted_conditions": nl2.get("extracted_conditions", []),
        "confidence": nl2.get("overall_confidence", 0),
        "key_point": "自动提取时间限制、信任阈值、审批要求等条件，生成条件表达式",
        "level": "nl_complex",
    })

    return {
        "title": "P2 工程化升级演示",
        "features": {
            "P2-7": "Ed25519 Challenge-Response — 挑战-响应认证，私钥不离开Agent",
            "P2-8": "Declarative Policy — 声明式策略配置，Cedar风格条件引擎",
            "P2-9": "SIEM Integration — Splunk/ELK/Datadog导出 + SOC2/HIPAA + OTel追踪",
            "P2-10": "NL Permission Translation — 自然语言→ACL规则自动翻译",
        },
        "steps": steps,
    }


def base64_encode_fake() -> str:
    import base64
    return base64.b64encode(b"fake_signature_data_32bytes!!").decode("ascii")


# === AgentPass Architecture Endpoints ===

@router.get("/architecture")
async def architecture_endpoint():
    return get_architecture()


@router.post("/core-innovation-demo")
async def core_innovation_demo_endpoint():
    return get_core_innovation_demo()


@router.get("/system-status")
async def system_status_endpoint():
    return get_system_status()


# === Six-Layer Real-Time Verification ===

class SixLayerVerifyRequest(BaseModel):
    agent_id: str = "doc_agent"
    action: str = "read:feishu_table:finance"
    input_text: str = ""
    trust_score: float = 0.85
    risk_score: float = 0.0
    role: str = "operator"
    delegation_chain: Optional[List[str]] = None
    blocked_at: str = ""
    auto_revoked: bool = False
    allowed: bool = True
    reason: str = ""


@router.post("/six-layer/verify")
async def six_layer_verify_endpoint(req: SixLayerVerifyRequest):
    v = verify_six_layers(
        agent_id=req.agent_id,
        action=req.action,
        input_text=req.input_text,
        trust_score=req.trust_score,
        risk_score=req.risk_score,
        role=req.role,
        delegation_chain=req.delegation_chain,
        blocked_at=req.blocked_at,
        auto_revoked=req.auto_revoked,
        allowed=req.allowed,
        reason=req.reason,
    )
    return v.to_dict()


@router.get("/six-layer/history")
async def six_layer_history_endpoint(limit: int = 20):
    return {"history": get_verification_history(limit)}


@router.post("/six-layer/live-attack-demo")
async def live_attack_demo_endpoint():
    return get_live_attack_demo()


# === Judge Verification Endpoints ===

@router.post("/judge/verify-all")
async def judge_verify_all_endpoint():
    return run_full_judge_verification()


@router.get("/judge/q1-a2a-schema")
async def judge_q1_endpoint():
    return verify_a2a_token_schema()


@router.get("/judge/q2-chain-unforgeable")
async def judge_q2_endpoint():
    return verify_chain_unforgeable()


@router.get("/judge/q3-prompt-is-iam")
async def judge_q3_endpoint():
    return verify_prompt_defense_is_iam()


@router.get("/judge/q4-no-api-bypass")
async def judge_q4_endpoint():
    return verify_no_api_bypass()


@router.get("/judge/q5-external-attack")
async def judge_q5_endpoint():
    return verify_external_agent_attack()


@router.get("/judge/q6-honest-framing")
async def judge_q6_endpoint():
    return verify_honest_capability_framing()


@router.get("/judge/q7-three-strategies")
async def judge_q7_endpoint():
    return verify_three_failure_strategies()


# === Standard Alignment + HITL + Killer Summary ===

class HITLSubmitRequest(BaseModel):
    agent_id: str
    action: str
    risk_score: float
    trust_score: float
    reason: str = ""


class HITLDecideRequest(BaseModel):
    review_id: str
    approved: bool
    reviewer: str = "admin"


@router.get("/standard-alignment")
async def standard_alignment_endpoint():
    return get_standard_alignment()


@router.get("/hitl/config")
async def hitl_config_endpoint():
    return get_hitl_config()


@router.post("/hitl/submit")
async def hitl_submit_endpoint(req: HITLSubmitRequest):
    return submit_hitl_review(req.agent_id, req.action, req.risk_score, req.trust_score, req.reason)


@router.post("/hitl/decide")
async def hitl_decide_endpoint(req: HITLDecideRequest):
    return decide_hitl_review(req.review_id, req.approved, req.reviewer)


@router.get("/hitl/queue")
async def hitl_queue_endpoint():
    return get_hitl_queue()


@router.get("/killer-summary")
async def killer_summary_endpoint():
    return get_killer_summary()


@router.post("/bypass-test")
async def bypass_test_endpoint():
    import subprocess
    try:
        result = subprocess.run(
            [sys.executable, "scripts/attack_bypass_test.py"],
            capture_output=True, text=True, timeout=30,
            cwd=r"c:\Users\Administrator\Desktop\Agent身份识别系统2.2",
        )
        return {
            "exit_code": result.returncode,
            "output": result.stdout[-2000:] if result.stdout else "",
            "all_passed": result.returncode == 0,
        }
    except Exception as e:
        return {"error": str(e)[:100], "all_passed": False}
