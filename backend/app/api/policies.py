from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import generate_identifier
from app.db.database import get_db
from app.models.policy import Policy
from app.models.trustee import Trustee
from app.schemas.policy import PolicyCreate, PolicyResponse


router = APIRouter(
    prefix="/api/policies",
    tags=["Policies"],
)


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=201,
)
def create_policy(
    data: PolicyCreate,
    db: Session = Depends(get_db),
):
    # ---------------------------------------------------------
    # 1. Check that all referenced trustees exist.
    # ---------------------------------------------------------

    trustees = db.scalars(
        select(Trustee).where(
            Trustee.id.in_(data.trustee_ids)
        )
    ).all()

    found_ids = {
        trustee.id
        for trustee in trustees
    }

    missing_ids = [
        trustee_id
        for trustee_id in data.trustee_ids
        if trustee_id not in found_ids
    ]

    if missing_ids:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "One or more trustees do not exist.",
                "missing_trustee_ids": missing_ids,
            },
        )

    # ---------------------------------------------------------
    # 2. Make sure trustees are active.
    # ---------------------------------------------------------

    inactive_trustees = [
        trustee.id
        for trustee in trustees
        if not trustee.active
    ]

    if inactive_trustees:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "One or more trustees are inactive.",
                "inactive_trustee_ids": inactive_trustees,
            },
        )

    # ---------------------------------------------------------
    # 3. Prevent duplicate trustee IDs.
    # ---------------------------------------------------------

    if len(data.trustee_ids) != len(set(data.trustee_ids)):
        raise HTTPException(
            status_code=400,
            detail="Duplicate trustee IDs are not allowed.",
        )

    # ---------------------------------------------------------
    # 4. Create the policy.
    # ---------------------------------------------------------

    policy = Policy(
        id=generate_identifier(),
        name=data.name,
        description=data.description,
        policy_expression=data.policy_expression,
        trustee_ids=data.trustee_ids,
        version=1,
        epoch=1,
        active=True,
        expiry_seconds=data.expiry_seconds,
        timelock_seconds=data.timelock_seconds,
    )

    db.add(policy)
    db.commit()
    db.refresh(policy)

    return policy


@router.get(
    "",
    response_model=list[PolicyResponse],
)
def list_policies(
    db: Session = Depends(get_db),
):
    policies = db.scalars(
        select(Policy).order_by(
            Policy.created_at
        )
    ).all()

    return list(policies)


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
)
def get_policy(
    policy_id: str,
    db: Session = Depends(get_db),
):
    policy = db.get(
        Policy,
        policy_id,
    )

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    return policy