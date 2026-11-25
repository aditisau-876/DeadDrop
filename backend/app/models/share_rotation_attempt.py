
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class ShareRotationAttempt(Base):
    __tablename__ = "share_rotation_attempts"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    policy_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    previous_epoch: Mapped[int] = mapped_column(
        nullable=False,
    )

    new_epoch: Mapped[int] = mapped_column(
        nullable=False,
    )

    # Contains encrypted share envelopes and commitments only.
    payload: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="PREPARED",
        index=True,
    )

    transaction_hash: Mapped[str | None] = mapped_column(
        String(66),
        nullable=True,
        index=True,
    )

    result: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    __table_args__ = (
        Index(
            "ix_rotation_attempt_policy_status_epoch",
            "policy_id",
            "status",
            "previous_epoch",
        ),
    )
