from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
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
    ForeignKey(
        "policies.id",
        name="fk_recovery_requests_policy_id",
    ),
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
        default=3,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )


class RecoveryApproval(Base):
    __tablename__ = "recovery_approvals"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    recovery_id: Mapped[str] = mapped_column(
    String(64),
    ForeignKey(
        "recovery_requests.id",
        name="fk_recovery_approvals_recovery_id",
    ),
    nullable=False,
)

    trustee_id: Mapped[str] = mapped_column(
    String(64),
    ForeignKey(
        "trustees.id",
        name="fk_recovery_approvals_trustee_id",
    ),
    nullable=False,
)

    # The trustee's approval signature.
    # Actual EIP-712 verification will be added later.
    signature: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # A trustee can approve a particular recovery request
    # only once.
    __table_args__ = (
        UniqueConstraint(
            "recovery_id",
            "trustee_id",
            name="uq_recovery_trustee_approval",
        ),
    )