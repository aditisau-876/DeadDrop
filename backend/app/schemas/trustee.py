from __future__ import annotations

from pydantic import BaseModel, Field


class TrusteeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: str = Field(min_length=1, max_length=80)
    wallet_address: str | None = None
    public_key: str | None = None


class TrusteeResponse(BaseModel):
    id: str
    name: str
    role: str
    wallet_address: str | None
    public_key: str | None
    active: bool