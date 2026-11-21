
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import require_roles
from app.db.database import get_db
from app.models.audit_log import AuditLog
from app.schemas.audit_log import AuditLogResponse


router = APIRouter(
    prefix="/api/audit-logs",
    tags=["Audit Logs"],
)


@router.get(
    "",
    response_model=list[AuditLogResponse],
)
def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    actor_user_id: str | None = Query(default=None),
    action: str | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    admin=Depends(require_roles("admin")),
):
    query = select(AuditLog)

    if actor_user_id:
        query = query.where(
            AuditLog.actor_user_id == actor_user_id
        )

    if action:
        query = query.where(
            AuditLog.action == action.upper()
        )

    if start_date:
        query = query.where(
            AuditLog.created_at >= start_date
        )

    if end_date:
        query = query.where(
            AuditLog.created_at <= end_date
        )

    query = (
        query
        .order_by(
            AuditLog.created_at.desc(),
            AuditLog.id.desc(),
        )
        .offset(offset)
        .limit(limit)
    )

    return list(db.scalars(query).all())
