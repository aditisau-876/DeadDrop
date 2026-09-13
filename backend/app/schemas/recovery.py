from __future__ import annotations

from pydantic import BaseModel, Field


class RecoveryCreate(BaseModel):
    policy_id: str
    reason: str = Field(min_length=1, max_length=1000)
    incident_hash: str = Field(min_length=1)


class RecoveryApproval(BaseModel):
    recovery_id: str
    trustee_id: str
    signature: str = Field(min_length=1)


class RecoveryResponse(BaseModel):
    id: str
    policy_id: str
    reason: str
    incident_hash: str
    status: str
    approvals: int
    required_approvals: int