
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None

    # Human-readable description for the dashboard.
    policy_expression: str = Field(min_length=1)

    # Machine-readable policy logic.
    policy_tree: dict[str, Any] | None = None

    trustee_ids: list[str] = Field(min_length=1)

    expiry_seconds: int | None = Field(default=None, gt=0)
    timelock_seconds: int | None = Field(default=None, ge=0)


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: str | None
    policy_expression: str
    policy_tree: dict[str, Any] | None = None
    trustee_ids: list[str]
    version: int
    epoch: int
    active: bool
    expiry_seconds: int | None
    timelock_seconds: int | None
