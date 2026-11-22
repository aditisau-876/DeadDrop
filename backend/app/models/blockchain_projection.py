from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class BlockchainRecoveryProjection(Base):
    """
    Rebuildable view of a recovery's confirmed on-chain state.

    This table is derived from BlockchainEvent records. It must not be
    treated as the source of truth for off-chain RecoveryRequest data.
    """

    __tablename__ = "blockchain_recovery_projections"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    chain_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    contract_address: Mapped[str] = mapped_column(
        String(42),
        nullable=False,
    )

    recovery_key: Mapped[str] = mapped_column(
        String(66),
        nullable=False,
        index=True,
    )

    recovery_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey(
            "recovery_requests.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    policy_key: Mapped[str | None] = mapped_column(
        String(66),
        nullable=True,
    )

    requester: Mapped[str | None] = mapped_column(
        String(42),
        nullable=True,
    )

    state: Mapped[str] = mapped_column(
        String(32),
        default="UNKNOWN",
        nullable=False,
        index=True,
    )

    approvals: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    execute_after: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    requested_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    cancelled_by: Mapped[str | None] = mapped_column(
        String(42),
        nullable=True,
    )

    artifact_hash: Mapped[str | None] = mapped_column(
        String(66),
        nullable=True,
    )

    last_event_block: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    last_event_transaction: Mapped[str] = mapped_column(
        String(66),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "chain_id",
            "contract_address",
            "recovery_key",
            name="uq_chain_recovery_projection",
        ),
    )