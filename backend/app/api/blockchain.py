
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from web3.exceptions import Web3Exception

from app.blockchain import BlockchainClient
from app.core.config import settings
from app.core.security import get_current_user
from app.db.database import get_db
from app.models.policy import Policy
from app.models.recovery import RecoveryRequest
from app.models.trustee import Trustee


router = APIRouter(
    prefix="/api/blockchain",
    tags=["Blockchain"],
)

blockchain = BlockchainClient(
    rpc_url=settings.blockchain_rpc_url,
    chain_id=settings.blockchain_chain_id,
    contract_address=settings.blockchain_verifying_contract_address,
)


def require_blockchain():
    try:
        blockchain._require_contract()
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc


def can_access_policy(user, policy: Policy, db: Session) -> bool:
    if user.role == "admin":
        return True

    if user.role == "owner":
        return policy.owner_user_id == user.id

    if user.role == "trustee":
        trustee = db.scalar(
            select(Trustee).where(
                Trustee.user_id == user.id
            )
        )

        return (
            trustee is not None
            and trustee.active
            and trustee.id in set(policy.trustee_ids or [])
        )

    return False


@router.get("/status")
def get_blockchain_status(
    user=Depends(get_current_user),
):
    return blockchain.get_status()


@router.get("/contract/policies/{policy_id}")
def get_onchain_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    policy = db.get(Policy, policy_id)

    if policy is None or not can_access_policy(
        user,
        policy,
        db,
    ):
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    require_blockchain()

    try:
        onchain = blockchain.get_policy(policy_id)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc
    except Web3Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to read the policy from the blockchain.",
        ) from exc

    return {
        "policy_id": policy_id,
        "database": {
            "version": policy.version,
            "epoch": policy.epoch,
            "active": policy.active,
            "trustee_count": len(policy.trustee_ids or []),
        },
        "blockchain": onchain,
        "synchronized": (
            onchain["exists"]
            and onchain["version"] == policy.version
            and onchain["epoch"] == policy.epoch
            and onchain["active"] == policy.active
        ),
        "warning": (
            None
            if onchain["exists"]
            else "This policy has not been registered on-chain."
        ),
    }


@router.get("/contract/recoveries/{recovery_id}")
def get_onchain_recovery(
    recovery_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    recovery = db.get(
        RecoveryRequest,
        recovery_id,
    )

    if recovery is None:
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    policy = db.get(
        Policy,
        recovery.policy_id,
    )

    if policy is None or not can_access_policy(
        user,
        policy,
        db,
    ):
        raise HTTPException(
            status_code=404,
            detail="Recovery request not found.",
        )

    require_blockchain()

    try:
        onchain = blockchain.get_recovery(recovery_id)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc
    except Web3Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to read the recovery from the blockchain.",
        ) from exc

    database_status = recovery.status

    status_matches = False

    if onchain["exists"]:
        status_matches = (
            (
                database_status in {"PENDING", "APPROVED"}
                and onchain["state"] == "REQUESTED"
            )
            or (
                database_status == "EXECUTED"
                and onchain["state"] == "EXECUTED"
            )
            or (
                database_status == "CANCELLED"
                and onchain["state"] == "CANCELLED"
            )
        )

    return {
        "recovery_id": recovery_id,
        "database": {
            "status": database_status,
            "approvals": recovery.approvals,
            "policy_version": recovery.policy_version,
            "policy_epoch": recovery.policy_epoch,
        },
        "blockchain": onchain,
        "status_matches": status_matches,
        "warning": (
            None
            if onchain["exists"]
            else "This recovery request has not been created on-chain."
        ),
    }


@router.get("/transactions/{transaction_hash}")
def verify_blockchain_transaction(
    transaction_hash: str,
    user=Depends(get_current_user),
):
    if not blockchain.connected:
        raise HTTPException(
            status_code=503,
            detail="Blockchain RPC is unavailable.",
        )

    try:
        return blockchain.verify_transaction(
            transaction_hash
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc
    except Web3Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to verify the blockchain transaction.",
        ) from exc
