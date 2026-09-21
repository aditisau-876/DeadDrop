from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Human-readable representation of the access structure.
    #
    # Example:
    # "(3 core trustees AND 1 external auditor) OR (all 5 trustees)"
    policy_expression: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # IDs of trustees participating in this policy.
    trustee_ids: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    # Current policy version.
    version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )

    # Cryptographic share-refresh epoch.
    epoch: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )

    # Whether this policy can currently be used.
    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Optional recovery expiry.
    expiry_seconds: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    # Optional emergency timelock.
    timelock_seconds: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )