from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import generate_identifier
from app.db.database import get_db
from app.models.asset import ProtectedAsset
from app.models.share import EncryptedShare
from app.models.trustee import Trustee
from app.schemas.share import (
    ShareCreate,
    ShareResponse,
)


router = APIRouter(
    prefix="/api/shares",
    tags=["Encrypted Shares"],
)


@router.post(
    "",
    response_model=ShareResponse,
    status_code=201,
)
def create_share(
    data: ShareCreate,
    db: Session = Depends(get_db),
):
    asset = db.get(
        ProtectedAsset,
        data.asset_id,
    )

    if asset is None:
        raise HTTPException(
            status_code=404,
            detail="Protected asset not found.",
        )

    trustee = db.get(
        Trustee,
        data.trustee_id,
    )

    if trustee is None:
        raise HTTPException(
            status_code=404,
            detail="Trustee not found.",
        )

    if not trustee.active:
        raise HTTPException(
            status_code=400,
            detail="Trustee is inactive.",
        )

    if data.epoch != asset.epoch:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Share epoch does not match asset epoch.",
                "asset_epoch": asset.epoch,
                "share_epoch": data.epoch,
            },
        )

    # Make sure the trustee belongs to the policy.
    policy_trustee_ids = set()

    # The policy is loaded through the asset.
    from app.models.policy import Policy

    policy = db.get(
        Policy,
        asset.policy_id,
    )

    if policy is None:
        raise HTTPException(
            status_code=500,
            detail="Asset policy could not be found.",
        )

    policy_trustee_ids = set(
        policy.trustee_ids
    )

    if data.trustee_id not in policy_trustee_ids:
        raise HTTPException(
            status_code=403,
            detail="Trustee is not assigned to this policy.",
        )

    # Prevent duplicate share registration.
    existing = db.scalar(
        select(EncryptedShare).where(
            EncryptedShare.asset_id == data.asset_id,
            EncryptedShare.trustee_id == data.trustee_id,
            EncryptedShare.epoch == data.epoch,
        )
    )

    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="A share already exists for this trustee and epoch.",
        )

    share = EncryptedShare(
        id=generate_identifier(),
        asset_id=data.asset_id,
        trustee_id=data.trustee_id,
        encrypted_share=data.encrypted_share,
        commitment=data.commitment,
        epoch=data.epoch,
    )

    db.add(share)
    db.commit()
    db.refresh(share)

    return ShareResponse(
        id=share.id,
        asset_id=share.asset_id,
        trustee_id=share.trustee_id,
        commitment=share.commitment,
        epoch=share.epoch,
        created_at=share.created_at.isoformat(),
    )