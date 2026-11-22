from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class BlockchainEvent(Base):
    __tablename__ = "blockchain_events"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    chain_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )

    contract_address: Mapped[str] = mapped_column(
        String(42),
        nullable=False,
        index=True,
    )

    block_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )

    block_hash: Mapped[str] = mapped_column(
        String(66),
        nullable=False,
    )

    transaction_hash: Mapped[str] = mapped_column(
        String(66),
        nullable=False,
    )

    transaction_index: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    log_index: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    event_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    event_args: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )

    block_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    indexed_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "chain_id",
            "contract_address",
            "transaction_hash",
            "log_index",
            name="uq_blockchain_event_log",
        ),
    )


class BlockchainSyncCheckpoint(Base):
    __tablename__ = "blockchain_sync_checkpoints"

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

    last_processed_block: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    last_block_hash: Mapped[str | None] = mapped_column(
        String(66),
        nullable=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "chain_id",
            "contract_address",
            name="uq_blockchain_sync_network_contract",
        ),
    )