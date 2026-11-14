
from __future__ import annotations

from pydantic import BaseModel, Field


class EncryptedShareInput(BaseModel):
    trustee_id: str = Field(min_length=1)
    encrypted_share: str = Field(min_length=1)
    commitment: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-fA-F]{64}$",
    )
    epoch: int = Field(ge=1)


class AssetProtectionCreate(BaseModel):
    policy_id: str = Field(min_length=1)
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None

    # AES-256-GCM encrypted data, encoded as Base64.
    ciphertext: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    aad: str | None = None
    threshold: int = Field(ge=2)

    # One encrypted share for every trustee in the policy.
    shares: list[EncryptedShareInput] = Field(min_length=2)


class AssetCreate(BaseModel):
    policy_id: str
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    ciphertext: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    aad: str | None = None
    epoch: int = Field(default=1, ge=1)


class AssetResponse(BaseModel):
    id: str
    policy_id: str
    name: str
    description: str | None
    epoch: int
    created_at: str
    threshold: int
