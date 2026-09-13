from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class RecoveryRequest(Base):
    __tablename__ = "recovery_requests"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    policy_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    incident_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="PENDING",
        nullable=False,
    )

    approvals: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    required_approvals: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )