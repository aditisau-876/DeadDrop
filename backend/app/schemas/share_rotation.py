
from __future__ import annotations

from pydantic import BaseModel, Field


class RotatedShareInput(BaseModel):
    trustee_id: str = Field(min_length=1)
    encrypted_share: str = Field(min_length=1)
    commitment: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-fA-F]{64}$",
    )


class AssetShareRotation(BaseModel):
    asset_id: str = Field(min_length=1)
    shares: list[RotatedShareInput] = Field(min_length=2)


class ShareRotationRequest(BaseModel):
    expected_epoch: int = Field(ge=1)

    # Every protected asset belonging to the policy must be
    # included so that the policy and its assets move together.
    assets: list[AssetShareRotation] = Field(min_length=1)


class ShareRotationResponse(BaseModel):
    policy_id: str
    previous_epoch: int
    new_epoch: int
    new_policy_version: int
    updated_asset_count: int
    inserted_share_count: int
    message: str


class OnchainShareRotationFinalizeRequest(ShareRotationRequest):
    transaction_hash: str = Field(min_length=64, max_length=66, pattern=r"^(0x)?[0-9a-fA-F]{64}$")
