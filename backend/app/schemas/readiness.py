from __future__ import annotations

from pydantic import BaseModel


class ShareReadinessResponse(BaseModel):
    policy_id: str
    trustee_id: str
    epoch: int
    commitment: str
    verified: bool