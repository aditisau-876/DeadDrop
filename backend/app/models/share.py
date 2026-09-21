from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class EncryptedShare(Base):
    __tablename__ = "encrypted_shares"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    asset_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    trustee_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    # Share encrypted for the trustee.
    #
    # The backend cannot reconstruct the plaintext share.
    encrypted_share: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # SHA-256 commitment to the original share.
    commitment: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    epoch: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "trustee_id",
            "epoch",
            name="uq_asset_trustee_epoch_share",
        ),
    )