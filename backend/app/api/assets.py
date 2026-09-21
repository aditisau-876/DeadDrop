from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import generate_identifier
from app.db.database import get_db
from app.models.asset import ProtectedAsset
from app.models.policy import Policy
from app.schemas.asset import (
    AssetCreate,
    AssetResponse,
)


router = APIRouter(
    prefix="/api/assets",
    tags=["Protected Assets"],
)


@router.post(
    "",
    response_model=AssetResponse,
    status_code=201,
)
def create_asset(
    data: AssetCreate,
    db: Session = Depends(get_db),
):
    policy = db.get(
        Policy,
        data.policy_id,
    )

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    if not policy.active:
        raise HTTPException(
            status_code=400,
            detail="Policy is inactive.",
        )

    asset = ProtectedAsset(
        id=generate_identifier(),
        policy_id=data.policy_id,
        name=data.name,
        description=data.description,
        ciphertext=data.ciphertext,
        nonce=data.nonce,
        aad=data.aad,
        epoch=data.epoch,
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return AssetResponse(
        id=asset.id,
        policy_id=asset.policy_id,
        name=asset.name,
        description=asset.description,
        epoch=asset.epoch,
        created_at=asset.created_at.isoformat(),
    )


@router.get(
    "",
    response_model=list[AssetResponse],
)
def list_assets(
    db: Session = Depends(get_db),
):
    assets = db.scalars(
        select(ProtectedAsset).order_by(
            ProtectedAsset.created_at
        )
    ).all()

    return [
        AssetResponse(
            id=asset.id,
            policy_id=asset.policy_id,
            name=asset.name,
            description=asset.description,
            epoch=asset.epoch,
            created_at=asset.created_at.isoformat(),
        )
        for asset in assets
    ]


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
):
    asset = db.get(
        ProtectedAsset,
        asset_id,
    )

    if asset is None:
        raise HTTPException(
            status_code=404,
            detail="Protected asset not found.",
        )

    return AssetResponse(
        id=asset.id,
        policy_id=asset.policy_id,
        name=asset.name,
        description=asset.description,
        epoch=asset.epoch,
        created_at=asset.created_at.isoformat(),
    )