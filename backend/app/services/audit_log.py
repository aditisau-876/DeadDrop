
from __future__ import annotations

import logging
from uuid import uuid4

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.models.audit_log import AuditLog
from app.models.user import User

logger = logging.getLogger(__name__)

AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def record_request(
    db: Session,
    request: Request,
    status_code: int,
) -> None:
    """
    Record metadata for a state-changing API request.

    Request bodies, passwords, tokens, and secret material
    are deliberately not stored.
    """

    method = request.method.upper()

    if method not in AUDITED_METHODS:
        return

    actor_user_id = None

    authorization = request.headers.get("authorization", "")

    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

        try:
            claims = decode_access_token(token)
            actor = db.get(User, claims.get("sub"))

            if actor is not None and actor.is_active:
                actor_user_id = actor.id

        except Exception:
            # Invalid or expired credentials are recorded as anonymous.
            actor_user_id = None

    client_ip = None

    if request.client is not None:
        client_ip = request.client.host

    user_agent = request.headers.get("user-agent")

    if user_agent:
        user_agent = user_agent[:2000]

    entry = AuditLog(
        id=uuid4().hex,
        actor_user_id=actor_user_id,
        action=method,
        route=request.url.path,
        status_code=status_code,
        ip_address=client_ip,
        user_agent=user_agent,
        request_id=uuid4().hex,
    )

    db.add(entry)
    db.commit()


def record_request_safely(
    db: Session,
    request: Request,
    status_code: int,
) -> None:
    """
    Audit failure must not turn a successful business request
    into a failed API response.
    """

    try:
        record_request(db, request, status_code)
    except Exception:
        db.rollback()
        logger.exception("Failed to persist an audit log entry.")
