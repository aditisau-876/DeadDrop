
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ShareReleaseChallengeRequest(BaseModel):
    recovery_id: str = Field(min_length=1, max_length=64)
    asset_id: str = Field(min_length=1, max_length=64)
    trustee_id: str = Field(min_length=1, max_length=64)


class ShareReleaseChallengeResponse(BaseModel):
    challenge_id: str
    expires_at: str
    typed_data: dict[str, Any]


class ShareReleaseRequest(BaseModel):
    challenge_id: str = Field(min_length=1, max_length=64)
    nonce: str = Field(min_length=1, max_length=128)
    recovery_id: str = Field(min_length=1, max_length=64)
    asset_id: str = Field(min_length=1, max_length=64)
    trustee_id: str = Field(min_length=1, max_length=64)
    signature: str = Field(min_length=1)


class ShareReleaseResponse(BaseModel):
    recovery_id: str
    asset_id: str
    policy_id: str
    trustee_id: str
    epoch: int
    encrypted_share: str
    commitment: str
    message: str
