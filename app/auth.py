from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, and_

from app.config import settings
from app import database, identity
from app.db import SessionLocal
from app.models import IssuedTokenRow

# Initialize AgentPass SDK adapter
from app.adapters import get_adapter
_agentpass = get_adapter(settings.JWT_SECRET)

security = HTTPBearer(auto_error=False)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        return _agentpass.verify_token(token)
    except Exception:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])


@dataclass
class AuthContext:
    agent: Dict[str, Any]
    token_id: str
    claims: Dict[str, Any]
    request_ip: str


def _exc(code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=code, detail=detail)


def issue_token(
    agent_id: str,
    role: str,
    bound_ip: Optional[str] = None,
    usage_limit: int = settings.DEFAULT_USAGE_LIMIT,
    expires_in_minutes: int = settings.TOKEN_EXPIRE_MINUTES,
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=expires_in_minutes)
    jti = str(uuid.uuid4())

    payload = {
        "sub": agent_id,
        "role": role,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "usage_limit": usage_limit,
        "type": "access",
    }
    if bound_ip:
        payload["bound_ip"] = bound_ip

    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    refresh_jti = str(uuid.uuid4())
    refresh_expires_at = now + timedelta(days=7)
    refresh_payload = {
        "sub": agent_id,
        "role": role,
        "jti": refresh_jti,
        "iat": int(now.timestamp()),
        "exp": int(refresh_expires_at.timestamp()),
        "type": "refresh",
        "access_jti": jti,
    }
    refresh_token = jwt.encode(refresh_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    with SessionLocal() as db:
        db.add(IssuedTokenRow(
            jti=jti,
            agent_id=agent_id,
            issued_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            active=1,
            bound_ip=bound_ip,
            usage_limit=usage_limit,
            usage_count=0,
            refresh_jti=refresh_jti,
        ))
        db.commit()

    return {
        "access_token": token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_at": expires_at.isoformat(),
        "jti": jti,
        "usage_limit": usage_limit,
        "bound_ip": bound_ip,
        "role": role,
    }


def validate_refresh_token(refresh_token: str) -> Dict[str, Any]:
    try:
        claims = jwt.decode(refresh_token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except ExpiredSignatureError as exc:
        raise _exc(401, "Refresh token expired.") from exc
    except InvalidTokenError as exc:
        raise _exc(401, "Invalid refresh token.") from exc

    if claims.get("type") != "refresh":
        raise _exc(400, "Provided token is not a refresh token.")

    refresh_jti = claims.get("jti")
    if not refresh_jti:
        raise _exc(401, "Malformed refresh token.")

    with SessionLocal() as db:
        row = db.execute(
            select(IssuedTokenRow).where(IssuedTokenRow.refresh_jti == refresh_jti)
        ).scalar_one_or_none()

    if not row or not row.active:
        raise _exc(401, "Refresh token is not active or has been revoked.")

    return claims


def resolve_token(token: str, request_ip: str) -> AuthContext:
    try:
        claims = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except ExpiredSignatureError as exc:
        raise _exc(401, "Token expired.") from exc
    except InvalidTokenError as exc:
        raise _exc(401, "Invalid token.") from exc

    if claims.get("type") == "refresh":
        raise _exc(400, "Use /auth/refresh endpoint for refresh tokens.")

    jti = claims.get("jti")
    agent_id = claims.get("sub")
    if not jti or not agent_id:
        raise _exc(401, "Malformed token.")

    with SessionLocal() as db:
        token_row = db.execute(
            select(IssuedTokenRow)
            .where(and_(IssuedTokenRow.jti == jti, IssuedTokenRow.active == 1))
        ).scalar_one_or_none()

        if not token_row:
            raise _exc(401, "Token is not active.")

        expires_at = datetime.fromisoformat(token_row.expires_at)
        if expires_at <= datetime.now(timezone.utc):
            raise _exc(401, "Token expired in token store.")

        bound_ip = token_row.bound_ip
        if bound_ip and bound_ip != request_ip:
            raise _exc(
                403,
                f"Token is bound to IP {bound_ip}, current request IP is {request_ip}.",
            )

        if token_row.usage_count >= token_row.usage_limit:
            raise _exc(403, "Token usage limit exceeded.")

        token_row.usage_count += 1
        db.commit()

    agent = identity.get_agent(agent_id)
    if not agent:
        raise _exc(401, "Agent no longer exists.")
    if agent["status"] != "active":
        raise _exc(403, f"Agent status is {agent['status']}.")

    return AuthContext(agent=agent, token_id=jti, claims=claims, request_ip=request_ip)


def introspect_token(jti: str) -> Optional[Dict[str, Any]]:
    return database.get_token_state(jti)


def revoke_token(jti: str) -> bool:
    return database.revoke_token(jti)


async def get_auth_context(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> AuthContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _exc(401, "Missing Bearer token in Authorization header.")
    request_ip = request.client.host if request.client else "unknown"
    return resolve_token(credentials.credentials, request_ip=request_ip)
