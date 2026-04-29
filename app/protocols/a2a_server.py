"""
A2A (Agent-to-Agent) Protocol Server Adapter

Implements the A2A protocol (Google, Linux Foundation) for inter-agent
communication and collaboration.

Key Components:
  - Agent Card: /.well-known/agent.json — describes capabilities, skills, endpoint
  - JSON-RPC 2.0: All requests/responses follow JSON-RPC 2.0 spec
  - Task Lifecycle: submitted → working → input-required → completed / failed / canceled
  - Messages: user/agent turns with Parts (TextPart, DataPart)
  - Artifacts: Agent outputs (documents, data, files)

Spec: https://a2a-protocol.org/v0.2.6/specification/
"""
from __future__ import annotations

import json
import logging
import uuid
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from app.config import settings

logger = logging.getLogger("agent_system")


TASK_STATES = ["submitted", "working", "input-required", "completed", "failed", "canceled"]


_TASKS: Dict[str, Dict[str, Any]] = {}
_TASK_MESSAGES: Dict[str, List[Dict[str, Any]]] = {}
_TASK_ARTIFACTS: Dict[str, List[Dict[str, Any]]] = {}


def get_agent_card() -> Dict[str, Any]:
    base_url = os.environ.get("FEISHU_PUBLIC_URL", f"http://127.0.0.1:{settings.PORT}")
    return {
        "schemaVersion": "0.2.6",
        "name": "Agent IAM Security Server",
        "description": "Zero-trust identity and access management for AI agents. Provides prompt injection defense, alignment checks, credential brokering, 4-level revocation, and governance audit.",
        "url": f"{base_url}/api/protocols/a2a",
        "preferredTransport": "jsonrpc",
        "provider": {
            "organization": "Agent IAM",
            "url": "https://github.com/agent-iam",
        },
        "version": "2.4.0",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "securitySchemes": {
            "bearer": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            },
            "api_key": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
            },
        },
        "security": [{"bearer": []}, {"api_key": []}],
        "skills": [
            {
                "id": "prompt-defense",
                "name": "Prompt Injection Defense",
                "description": "3-layer fusion engine (rules + semantic + behavioral) for detecting prompt injection attacks",
                "tags": ["security", "prompt-injection", "defense"],
                "examples": [
                    "Check if this prompt contains an injection attack",
                    "Analyze this message for security threats",
                ],
            },
            {
                "id": "alignment-check",
                "name": "Output Alignment Check",
                "description": "Verify agent output aligns with original user intent, detecting goal hijacking, indirect injection, and DLP leaks",
                "tags": ["security", "alignment", "output-defense"],
                "examples": [
                    "Check if this agent output is aligned with the user's intent",
                    "Detect if the agent was hijacked",
                ],
            },
            {
                "id": "iam-check",
                "name": "Identity & Access Management",
                "description": "RBAC + ABAC + time-based + dynamic policy engine with trust scoring",
                "tags": ["iam", "authorization", "trust"],
                "examples": [
                    "Check if agent has permission for this action",
                    "Get the trust score for this agent",
                ],
            },
            {
                "id": "delegation",
                "name": "Secure Delegation",
                "description": "JWT-based delegation chain with capability scoping, depth limits, and one-time use tokens",
                "tags": ["delegation", "chain", "token"],
                "examples": [
                    "Create a delegation token for data_agent",
                    "Delegate read access to another agent",
                ],
            },
            {
                "id": "revocation",
                "name": "4-Level Revocation",
                "description": "Token-level, Agent-level, Task-level, and Chain-cascade revocation",
                "tags": ["revocation", "security", "cascade"],
                "examples": [
                    "Revoke all tokens for this agent",
                    "Cascade revoke this delegation chain",
                ],
            },
            {
                "id": "credential-broker",
                "name": "Credential Broker",
                "description": "Agents never touch real credentials. Broker injects credentials at call time, returns only results.",
                "tags": ["credentials", "broker", "zero-trust"],
                "examples": [
                    "Request access to feishu API",
                    "Execute a bitable query via broker",
                ],
            },
            {
                "id": "governance-audit",
                "name": "Governance & Audit",
                "description": "SHA-256 hash chain audit logs, governance events, and compliance reporting",
                "tags": ["audit", "governance", "compliance"],
                "examples": [
                    "Get recent governance events",
                    "Retrieve audit log entries",
                ],
            },
        ],
    }


import os


def handle_a2a_request(request: Dict[str, Any]) -> Dict[str, Any]:
    jsonrpc = request.get("jsonrpc", "2.0")
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})

    if method == "message/send":
        return _handle_send_task(req_id, params)
    elif method == "tasks/get":
        return _handle_get_task(req_id, params)
    elif method == "tasks/cancel":
        return _handle_cancel_task(req_id, params)
    elif method == "tasks/list":
        return _handle_list_tasks(req_id, params)
    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def _handle_send_task(req_id: Any, params: Dict) -> Dict[str, Any]:
    task_id = params.get("id", f"task_{uuid.uuid4().hex[:12]}")
    message = params.get("message", {})
    context_id = params.get("contextId")

    _TASKS[task_id] = {
        "id": task_id,
        "status": {"state": "working"},
        "contextId": context_id,
        "history": [message],
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    _TASK_MESSAGES[task_id] = [message]

    user_text = _extract_text(message)
    agent_result = _process_agent_message(user_text, task_id)

    agent_message = {
        "role": "agent",
        "parts": [{"type": "text", "text": agent_result}],
        "messageId": f"msg_{uuid.uuid4().hex[:8]}",
    }
    _TASK_MESSAGES[task_id].append(agent_message)

    artifact = None
    if len(agent_result) > 100:
        artifact = {
            "name": "security-analysis",
            "parts": [{"type": "text", "text": agent_result}],
            "artifactId": f"art_{uuid.uuid4().hex[:8]}",
        }
        _TASK_ARTIFACTS.setdefault(task_id, []).append(artifact)

    _TASKS[task_id]["status"] = {"state": "completed"}
    _TASKS[task_id]["history"] = _TASK_MESSAGES[task_id]

    result = {
        "id": task_id,
        "status": _TASKS[task_id]["status"],
        "history": _TASK_MESSAGES[task_id],
    }
    if artifact:
        result["artifacts"] = [artifact]
    if context_id:
        result["contextId"] = context_id

    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _handle_get_task(req_id: Any, params: Dict) -> Dict[str, Any]:
    task_id = params.get("id", "")
    task = _TASKS.get(task_id)
    if not task:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32001, "message": f"Task not found: {task_id}"},
        }
    result = {
        "id": task_id,
        "status": task["status"],
        "history": task.get("history", []),
    }
    if task_id in _TASK_ARTIFACTS:
        result["artifacts"] = _TASK_ARTIFACTS[task_id]
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _handle_cancel_task(req_id: Any, params: Dict) -> Dict[str, Any]:
    task_id = params.get("id", "")
    task = _TASKS.get(task_id)
    if not task:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32001, "message": f"Task not found: {task_id}"},
        }
    task["status"] = {"state": "canceled"}
    return {"jsonrpc": "2.0", "id": req_id, "result": {"id": task_id, "status": task["status"]}}


def _handle_list_tasks(req_id: Any, params: Dict) -> Dict[str, Any]:
    tasks = []
    for tid, task in _TASKS.items():
        tasks.append({"id": tid, "status": task["status"]})
    return {"jsonrpc": "2.0", "id": req_id, "result": {"tasks": tasks}}


def _extract_text(message: Dict) -> str:
    parts = message.get("parts", [])
    texts = []
    for part in parts:
        if part.get("type") == "text":
            texts.append(part.get("text", ""))
    return " ".join(texts)


def _process_agent_message(text: str, task_id: str) -> str:
    text_lower = text.lower()

    if any(kw in text_lower for kw in ["prompt", "injection", "注入", "攻击"]):
        try:
            from agentpass_sdk.src.agentpass.prompt_defense import PromptDefenseEngine
            engine = PromptDefenseEngine()
            result = engine.analyze(text)
            return json.dumps({
                "service": "prompt-defense",
                "analysis": result,
                "task_id": task_id,
            }, indent=2, ensure_ascii=False)
        except Exception as e:
            return f"Prompt defense analysis error: {e}"

    elif any(kw in text_lower for kw in ["alignment", "对齐", "hijack", "劫持"]):
        return json.dumps({
            "service": "alignment-check",
            "message": "Use defense.check_alignment MCP tool with original_message and agent_output parameters",
            "task_id": task_id,
        }, indent=2, ensure_ascii=False)

    elif any(kw in text_lower for kw in ["permission", "权限", "trust", "信任"]):
        try:
            from app.delegation.engine import get_trust_score, CAPABILITY_AGENTS
            scores = {aid: get_trust_score(aid) for aid in CAPABILITY_AGENTS}
            return json.dumps({
                "service": "iam",
                "trust_scores": scores,
                "task_id": task_id,
            }, indent=2, ensure_ascii=False)
        except Exception as e:
            return f"IAM check error: {e}"

    elif any(kw in text_lower for kw in ["credential", "凭证", "broker", "key"]):
        return json.dumps({
            "service": "credential-broker",
            "message": "Use broker.request_access or broker.execute MCP tools",
            "task_id": task_id,
        }, indent=2, ensure_ascii=False)

    elif any(kw in text_lower for kw in ["revoke", "撤销", "cascade"]):
        return json.dumps({
            "service": "4-level-revocation",
            "levels": {"L1": "token", "L2": "agent", "L3": "task", "L4": "chain-cascade"},
            "message": "Use iam.revoke MCP tool with cascade=true for L4",
            "task_id": task_id,
        }, indent=2, ensure_ascii=False)

    else:
        return json.dumps({
            "service": "agent-iam",
            "message": "Agent IAM Security Server ready. Available skills: prompt-defense, alignment-check, iam-check, delegation, revocation, credential-broker, governance-audit",
            "task_id": task_id,
        }, indent=2, ensure_ascii=False)


def get_a2a_server_info() -> Dict[str, Any]:
    return {
        "protocol": "A2A",
        "version": "0.2.6",
        "server_name": "Agent IAM Security A2A Server",
        "skills_count": len(get_agent_card()["skills"]),
        "skills": [s["id"] for s in get_agent_card()["skills"]],
        "transport": "HTTP + JSON-RPC 2.0",
        "endpoints": {
            "agent_card": "/.well-known/agent.json",
            "a2a": "/api/protocols/a2a",
        },
        "task_states": TASK_STATES,
    }
