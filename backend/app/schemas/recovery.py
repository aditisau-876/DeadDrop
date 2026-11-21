
from __future__ import annotations

from pydantic import BaseModel, Field


class RecoveryCreate(BaseModel):
    policy_id: str = Field(min_length=1, max_length=64)

    reason: str = Field(
        min_length=1,
        max_length=1000,
    )

    incident_hash: str = Field(
        min_length=1,
        max_length=128,
    )


class RecoveryApproval(BaseModel):
    recovery_id: str = Field(min_length=1, max_length=64)

    trustee_id: str = Field(min_length=1, max_length=64)

    signature: str = Field(
        min_length=1,
        max_length=1024,
    )


class RecoveryCancel(BaseModel):
    reason: str = Field(
        min_length=1,
        max_length=500,
    )


class RecoveryResponse(BaseModel):
    id: str
    policy_id: str
    reason: str
    incident_hash: str

    status: str

    approvals: int
    required_approvals: int

    policy_version: int
    policy_epoch: int

    expires_at: str | None = None
    execute_after: str | None = None

    cancelled_at: str | None = None
    cancellation_reason: str | None = None

    completed_at: str | None = None

    can_release: bool = False
