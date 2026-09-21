from __future__ import annotations

from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    policy_id: str

    name: str = Field(
        min_length=1,
        max_length=120,
    )

    description: str | None = None

    # AES-GCM ciphertext.
    ciphertext: str = Field(
        min_length=1,
    )

    nonce: str = Field(
        min_length=1,
    )

    aad: str | None = None

    epoch: int = Field(
        default=1,
        ge=1,
    )


class AssetResponse(BaseModel):
    id: str
    policy_id: str
    name: str
    description: str | None
    epoch: int
    created_at: str