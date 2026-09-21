from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class ProtectedAsset(Base):
    __tablename__ = "protected_assets"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    policy_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # AES-GCM ciphertext.
    #
    # The plaintext secret itself is NEVER stored here.
    ciphertext: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Base64 encoded AES-GCM nonce.
    nonce: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    # Optional encoded AAD used during encryption.
    aad: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Cryptographic share epoch.
    epoch: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )