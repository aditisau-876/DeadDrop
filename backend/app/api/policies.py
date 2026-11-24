from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    ensure_owner_or_admin,
    generate_identifier,
    get_current_user,
    require_roles,
)
from app.db.database import get_db
from app.api.blockchain import blockchain
from app.models.policy import Policy
from app.models.recovery import RecoveryRequest
from app.models.trustee import Trustee
from app.schemas.policy import (
    PolicyCreate,
    PolicyResponse,
    PolicyUpdate,
)
from app.services.access_structure import validate_policy_tree


router = APIRouter(
    prefix="/api/policies",
    dependencies=[Depends(get_current_user)],
    tags=["Policies"],
)

ACTIVE_RECOVERY_STATUSES = {"PENDING", "APPROVED"}


def get_policy_or_404(
    db: Session,
    policy_id: str,
) -> Policy:
    policy = db.scalar(
        select(Policy)
        .where(Policy.id == policy_id)
        .with_for_update()
    )

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    return policy


def ensure_policy_not_registered_onchain(policy_id: str) -> None:
    """Prevent DB-only edits that would silently desynchronize Solidity state."""
    if not blockchain.contract_address_configured:
        return
    if not blockchain.connected:
        raise HTTPException(
            status_code=503,
            detail="Blockchain RPC is unavailable. Policy changes are blocked until on-chain synchronization can be checked.",
        )
    try:
        onchain = blockchain.get_policy(policy_id)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if onchain.get("exists"):
        raise HTTPException(
            status_code=409,
            detail=(
                "This policy is already registered on-chain. Database-only edits are blocked "
                "because the current contract does not yet expose a complete policy-update "
                "transaction for trustee/quorum/version synchronization. Create a new policy "
                "or use a future coordinated on-chain policy migration."
            ),
        )


def ensure_no_active_recoveries(
    db: Session,
    policy_id: str,
) -> None:
    recovery = db.scalar(
        select(RecoveryRequest.id)
        .where(
            RecoveryRequest.policy_id == policy_id,
            RecoveryRequest.status.in_(ACTIVE_RECOVERY_STATUSES),
        )
        .limit(1)
    )

    if recovery is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "This policy has an active recovery request. "
                "Wait until it is completed, cancelled, or expired "
                "before modifying the policy."
            ),
        )


def load_and_validate_trustees(
    db: Session,
    trustee_ids: list[str],
) -> list[Trustee]:
    if not trustee_ids:
        raise HTTPException(
            status_code=400,
            detail="At least one trustee must be assigned.",
        )

    if len(trustee_ids) != len(set(trustee_ids)):
        raise HTTPException(
            status_code=400,
            detail="Duplicate trustee IDs are not allowed.",
        )

    trustees = db.scalars(
        select(Trustee)
        .where(Trustee.id.in_(trustee_ids))
        .with_for_update()
    ).all()

    found_ids = {trustee.id for trustee in trustees}

    missing_ids = [
        trustee_id
        for trustee_id in trustee_ids
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

    inactive_ids = [
        trustee.id
        for trustee in trustees
        if not trustee.active
    ]

    if inactive_ids:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Inactive trustees cannot be assigned.",
                "inactive_trustee_ids": inactive_ids,
            },
        )

    return trustees


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=201,
)
def create_policy(
    data: PolicyCreate,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    trustees = load_and_validate_trustees(
        db,
        data.trustee_ids,
    )

    if data.policy_tree is not None:
        try:
            validate_policy_tree(
                data.policy_tree,
                set(data.trustee_ids),
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=str(exc),
            ) from exc

    policy = Policy(
        id=generate_identifier(),
        owner_user_id=user.id,
        name=data.name,
        description=data.description,
        policy_expression=data.policy_expression,
        policy_tree=data.policy_tree,
        trustee_ids=[trustee.id for trustee in trustees],
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
    user=Depends(get_current_user),
):
    query = select(Policy).order_by(Policy.created_at)

    if user.role != "admin":
        query = query.where(
            Policy.owner_user_id == user.id
        )

    return list(db.scalars(query).all())


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
)
def get_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    policy = db.get(Policy, policy_id)

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    ensure_owner_or_admin(
        user,
        policy.owner_user_id,
    )

    return policy


@router.patch(
    "/{policy_id}",
    response_model=PolicyResponse,
)
def update_policy(
    policy_id: str,
    data: PolicyUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    policy = get_policy_or_404(db, policy_id)

    ensure_owner_or_admin(
        user,
        policy.owner_user_id,
    )
    ensure_policy_not_registered_onchain(policy.id)

    if data.expected_version != policy.version:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Policy version conflict.",
                "current_version": policy.version,
                "submitted_version": data.expected_version,
            },
        )

    updates = data.dict(exclude_unset=True)
    updates.pop("expected_version", None)
    for required_field in ("name","policy_expression","trustee_ids","active"):
        if required_field in updates and updates[required_field] is None:
            raise HTTPException(
                status_code=422,
                detail=f"{required_field} cannot be null.",
            )

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No policy changes were supplied.",
        )

    ensure_no_active_recoveries(
        db,
        policy.id,
    )

    new_trustee_ids = updates.get(
        "trustee_ids",
        policy.trustee_ids,
    )

    if new_trustee_ids is None:
        new_trustee_ids = policy.trustee_ids

    if "trustee_ids" in updates:
        load_and_validate_trustees(
            db,
            new_trustee_ids,
        )
    elif updates.get("active") is True:
        load_and_validate_trustees(
            db,
            policy.trustee_ids,
        )

    new_policy_tree = updates.get(
        "policy_tree",
        policy.policy_tree,
    )

    if new_policy_tree is not None:
        try:
            validate_policy_tree(
                new_policy_tree,
                set(new_trustee_ids),
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=str(exc),
            ) from exc

    for field, value in updates.items():
        setattr(policy, field, value)

    policy.version += 1

    db.add(policy)
    db.commit()
    db.refresh(policy)

    return policy


@router.post(
    "/{policy_id}/deactivate",
    response_model=PolicyResponse,
)
def deactivate_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    policy = get_policy_or_404(db, policy_id)

    ensure_owner_or_admin(
        user,
        policy.owner_user_id,
    )
    ensure_policy_not_registered_onchain(policy.id)

    if not policy.active:
        return policy

    ensure_no_active_recoveries(
        db,
        policy.id,
    )

    policy.active = False
    policy.version += 1

    db.commit()
    db.refresh(policy)

    return policy
