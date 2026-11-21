from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field

class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    policy_expression: str = Field(min_length=1)
    policy_tree: dict[str, Any] | None = None
    trustee_ids: list[str] = Field(min_length=1)
    expiry_seconds: int | None = Field(default=None, gt=0)
    timelock_seconds: int | None = Field(default=None, ge=0)

class PolicyUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None
    policy_expression: str | None = Field(default=None, min_length=1)
    policy_tree: dict[str, Any] | None = None
    trustee_ids: list[str] | None = Field(default=None, min_length=1)
    expiry_seconds: int | None = Field(default=None, gt=0)
    timelock_seconds: int | None = Field(default=None, ge=0)
    active: bool | None = None


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
