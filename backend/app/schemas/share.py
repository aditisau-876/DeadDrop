from __future__ import annotations

from pydantic import BaseModel, Field


class ShareCreate(BaseModel):
    asset_id: str

    trustee_id: str

    encrypted_share: str = Field(
        min_length=1,
    )

    commitment: str = Field(
        min_length=64,
        max_length=64,
    )

    epoch: int = Field(
        ge=1,
    )


class ShareResponse(BaseModel):
    id: str
    asset_id: str
    trustee_id: str
    commitment: str
    epoch: int
    created_at: str