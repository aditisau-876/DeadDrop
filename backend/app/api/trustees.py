from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import generate_identifier
from app.db.database import get_db
from app.models.trustee import Trustee
from app.schemas.trustee import TrusteeCreate, TrusteeResponse


router = APIRouter(
    prefix="/api/trustees",
    tags=["Trustees"],
)


@router.post(
    "",
    response_model=TrusteeResponse,
    status_code=201,
)
def create_trustee(
    data: TrusteeCreate,
    db: Session = Depends(get_db),
):
    trustee = Trustee(
        id=generate_identifier(),
        name=data.name,
        role=data.role,
        wallet_address=data.wallet_address,
        public_key=data.public_key,
        active=True,
    )

    db.add(trustee)
    db.commit()
    db.refresh(trustee)

    return trustee


@router.get(
    "",
    response_model=list[TrusteeResponse],
)
def list_trustees(
    db: Session = Depends(get_db),
):
    trustees = db.scalars(
        select(Trustee).order_by(Trustee.created_at)
    ).all()

    return list(trustees)


@router.get(
    "/{trustee_id}",
    response_model=TrusteeResponse,
)
def get_trustee(
    trustee_id: str,
    db: Session = Depends(get_db),
):
    trustee = db.get(Trustee, trustee_id)

    if trustee is None:
        raise HTTPException(
            status_code=404,
            detail="Trustee not found.",
        )

    return trustee