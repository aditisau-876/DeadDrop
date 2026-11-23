
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    generate_identifier,
    get_current_user,
    require_roles,
)
from app.db.database import get_db
from app.models.policy import Policy
from app.models.trustee import Trustee
from app.schemas.trustee import (
    TrusteeCreate,
    TrusteeResponse,
    TrusteeStatusUpdate,
)


router = APIRouter(
    prefix="/api/trustees",
    dependencies=[Depends(get_current_user)],
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
    user=Depends(require_roles("admin")),
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
    user=Depends(get_current_user),
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
    user=Depends(get_current_user),
):
    trustee = db.get(Trustee, trustee_id)

    if trustee is None:
        raise HTTPException(
            status_code=404,
            detail="Trustee not found.",
        )

    return trustee

@router.get(
    "/me",
    response_model=TrusteeResponse,
)
def get_my_trustee_profile(
    db: Session = Depends(get_db),
    user=Depends(require_roles("trustee")),
):
    """
    Return the trustee profile linked to the authenticated account.
    """

    trustee = db.scalar(
        select(Trustee).where(
            Trustee.user_id == user.id
        )
    )

    if trustee is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No trustee profile is linked to this account. "
                "Contact the DeadDrop administrator."
            ),
        )

    if not trustee.active:
        raise HTTPException(
            status_code=403,
            detail="Your trustee profile is inactive.",
        )

    return trustee


@router.patch(
    "/{trustee_id}/status",
    response_model=TrusteeResponse,
)
def update_trustee_status(
    trustee_id: str,
    data: TrusteeStatusUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_roles("admin")),
):
    trustee = db.scalar(
        select(Trustee)
        .where(Trustee.id == trustee_id)
        .with_for_update()
    )

    if trustee is None:
        raise HTTPException(
            status_code=404,
            detail="Trustee not found.",
        )

    if trustee.active == data.active:
        return trustee

    if not data.active:
        active_policies = db.scalars(select(Policy).where(Policy.active.is_(True))).all()
        assigned_policy = next(
            (
                policy
                for policy in active_policies
                if trustee.id in (policy.trustee_ids or [])
            ),
            None,
        )

        if assigned_policy is not None:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": (
                        "This trustee is assigned to an active policy. "
                        "Update or deactivate the policy before "
                        "deactivating this trustee."
                    ),
                    "policy_id": assigned_policy.id,
                },
            )


        if assigned_policy is not None:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": (
                        "This trustee is assigned to an active policy. "
                        "Update or deactivate the policy before "
                        "deactivating this trustee."
                    ),
                    "policy_id": assigned_policy,
                },
            )

    trustee.active = data.active

    db.commit()
    db.refresh(trustee)

    return trustee
