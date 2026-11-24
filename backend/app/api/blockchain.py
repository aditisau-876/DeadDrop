
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session
from web3 import Web3
from web3.exceptions import Web3Exception

from app.blockchain import BlockchainClient
from app.core.config import settings
from app.core.security import get_current_user
from app.db.database import get_db
from app.models.policy import Policy
from app.models.recovery import RecoveryApproval as RecoveryApprovalModel, RecoveryRequest
from app.models.trustee import Trustee
from app.models.asset import ProtectedAsset
from app.models.share import EncryptedShare


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


class TransactionVerificationInput(BaseModel):
    transaction_hash: str


class RecoveryExecutionVerificationInput(BaseModel):
    transaction_hash: str
    artifact_hash: str


def _canonical_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return Web3.to_hex(Web3.keccak(text=encoded))


def _flat_threshold(policy: Policy) -> int:
    """Return the on-chain flat threshold or reject richer policy trees."""
    tree = policy.policy_tree
    if not isinstance(tree, dict) or tree.get("type") != "THRESHOLD":
        raise HTTPException(
            status_code=422,
            detail=(
                "This policy uses a composable AND/OR policy tree. "
                "The current Solidity recovery contract supports only a "
                "single flat THRESHOLD node. Simplify the policy to a flat "
                "threshold before registering it on-chain."
            ),
        )
    children = tree.get("children")
    threshold = tree.get("threshold")
    if (
        not isinstance(children, list)
        or not children
        or not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold < 1
        or threshold > len(children)
        or any(
            not isinstance(child, dict)
            or child.get("type") != "LEAF"
            or not isinstance(child.get("trustee_id"), str)
            for child in children
        )
    ):
        raise HTTPException(
            status_code=422,
            detail="Only a flat THRESHOLD policy with LEAF trustee children can be registered on-chain.",
        )
    tree_ids = [child["trustee_id"] for child in children]
    if len(tree_ids) != len(set(tree_ids)) or set(tree_ids) != set(policy.trustee_ids or []):
        raise HTTPException(
            status_code=422,
            detail="The policy tree must contain every assigned trustee exactly once.",
        )
    return threshold


def _policy_registration_data(db: Session, policy: Policy) -> dict[str, Any]:
    trustee_ids = list(policy.trustee_ids or [])
    if len(trustee_ids) > 16:
        raise HTTPException(status_code=422, detail="The current browser share scheme supports at most 16 trustees per policy.")
    trustees = db.scalars(
        select(Trustee).where(Trustee.id.in_(trustee_ids))
    ).all()
    by_id = {item.id: item for item in trustees}
    if len(by_id) != len(trustee_ids):
        raise HTTPException(status_code=409, detail="One or more assigned trustees no longer exist.")
    wallets: list[str] = []
    for trustee_id in trustee_ids:
        trustee = by_id[trustee_id]
        if not trustee.active:
            raise HTTPException(status_code=409, detail=f"Trustee {trustee.name} is inactive.")
        if not trustee.wallet_address or not Web3.is_address(trustee.wallet_address):
            raise HTTPException(status_code=422, detail=f"Trustee {trustee.name} needs a valid Ethereum wallet address before on-chain registration.")
        wallets.append(Web3.to_checksum_address(trustee.wallet_address))
    if len(set(wallets)) != len(wallets):
        raise HTTPException(status_code=422, detail="Two or more trustees use the same wallet address.")
    quorum = _flat_threshold(policy)
    timelock = int(policy.timelock_seconds or 0)
    if timelock < 0 or timelock >= 2**64:
        raise HTTPException(status_code=422, detail="Policy timelock is outside the supported range.")
    policy_document = {
        "id": policy.id,
        "name": policy.name,
        "description": policy.description,
        "policy_expression": policy.policy_expression,
        "policy_tree": policy.policy_tree,
        "trustee_ids": trustee_ids,
        "version": policy.version,
        "epoch": policy.epoch,
        "active": policy.active,
        "expiry_seconds": policy.expiry_seconds,
        "timelock_seconds": policy.timelock_seconds,
    }
    return {
        "policy_id": policy.id,
        "policy_hash": _canonical_hash(policy_document),
        "trustee_wallets": wallets,
        "trustee_ids": trustee_ids,
        "quorum": quorum,
        "timelock_seconds": timelock,
        "chain_id": settings.blockchain_chain_id,
        "contract_address": blockchain.contract_address,
        "function_signature": "registerPolicy(string,bytes32,address[],uint16,uint64)",
    }


@router.get("/registration/policies/{policy_id}")
def get_policy_registration_payload(
    policy_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    policy = db.get(Policy, policy_id)
    if policy is None or not can_access_policy(user, policy, db):
        raise HTTPException(status_code=404, detail="Policy not found.")
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only the policy owner can register a policy.")
    if not policy.active:
        raise HTTPException(status_code=409, detail="Inactive policies cannot be registered.")
    require_blockchain()
    try:
        if blockchain.get_policy(policy.id).get("exists"):
            raise HTTPException(status_code=409, detail="This policy is already registered on-chain.")
        payload = _policy_registration_data(db, policy)
        payload["contract_owner"] = blockchain.contract.functions.owner().call()
        return payload
    except HTTPException:
        raise
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Web3Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to prepare policy registration.") from exc


@router.post("/registration/policies/{policy_id}/verify")
def verify_policy_registration(
    policy_id: str,
    data: TransactionVerificationInput,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    policy = db.get(Policy, policy_id)
    if policy is None or not can_access_policy(user, policy, db):
        raise HTTPException(status_code=404, detail="Policy not found.")
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only the policy owner can verify registration.")
    require_blockchain()
    try:
        expected = _policy_registration_data(db, policy)
        tx = blockchain.verify_transaction(data.transaction_hash)
        if not tx.get("found") or not tx.get("mined") or not tx.get("successful") or not tx.get("to_deadrop_contract"):
            raise HTTPException(status_code=409, detail="The supplied transaction is not a successful mined transaction to the configured DeadDrop contract.")
        transaction = blockchain.web3.eth.get_transaction(data.transaction_hash)
        decoded_function, decoded_args = blockchain.contract.decode_function_input(transaction["input"])
        if decoded_function.fn_name != "registerPolicy" or len(decoded_args) != 5:
            raise HTTPException(status_code=409, detail="The supplied transaction did not call the new asset-independent registerPolicy overload.")
        submitted_wallets = [Web3.to_checksum_address(item) for item in decoded_args["trusteeWallets"]]
        if (
            decoded_args["policyId"] != policy_id
            or Web3.to_hex(decoded_args["policyHash"]).lower() != expected["policy_hash"].lower()
            or submitted_wallets != expected["trustee_wallets"]
            or int(decoded_args["quorum"]) != expected["quorum"]
            or int(decoded_args["timelockDuration"]) != expected["timelock_seconds"]
        ):
            raise HTTPException(status_code=409, detail="The transaction arguments do not match the canonical policy registration payload.")
        onchain = blockchain.get_policy(policy_id)
        if not onchain.get("exists"):
            raise HTTPException(status_code=409, detail="Policy does not exist on-chain after this transaction.")
        if (
            onchain["policy_hash"].lower() != expected["policy_hash"].lower()
            or int(onchain["quorum"]) != expected["quorum"]
            or int(onchain["timelock_duration"]) != expected["timelock_seconds"]
            or int(onchain["trustee_count"]) != len(expected["trustee_wallets"])
            or not all(blockchain.is_trustee(policy_id, wallet) for wallet in expected["trustee_wallets"])
        ):
            raise HTTPException(status_code=409, detail="On-chain policy data does not match the current database policy. Do not mark this policy registered.")
        return {"verified": True, "policy_id": policy_id, "transaction": tx, "blockchain": onchain}
    except HTTPException:
        raise
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Web3Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to verify policy registration on-chain.") from exc


def _asset_registration_data(db: Session, asset: ProtectedAsset) -> dict[str, Any]:
    policy = db.get(Policy, asset.policy_id)
    if policy is None:
        raise HTTPException(status_code=409, detail="The asset's policy no longer exists.")
    trustee_ids = list(policy.trustee_ids or [])
    trustees = db.scalars(select(Trustee).where(Trustee.id.in_(trustee_ids))).all()
    trustee_by_id = {item.id: item for item in trustees}
    shares = db.scalars(select(EncryptedShare).where(EncryptedShare.asset_id == asset.id)).all()
    share_by_id = {item.trustee_id: item for item in shares}
    if set(share_by_id) != set(trustee_ids):
        raise HTTPException(status_code=409, detail="Asset must have exactly one encrypted share for every policy trustee before on-chain commitment registration.")
    wallets: list[str] = []
    commitments: list[str] = []
    for trustee_id in trustee_ids:
        trustee = trustee_by_id.get(trustee_id)
        share = share_by_id[trustee_id]
        if trustee is None or not trustee.active:
            raise HTTPException(status_code=409, detail=f"Trustee {trustee_id} is missing or inactive.")
        if not trustee.wallet_address or not Web3.is_address(trustee.wallet_address):
            raise HTTPException(status_code=422, detail=f"Trustee {trustee.name} needs a valid wallet address.")
        if share.epoch != asset.epoch or len(share.commitment) != 64:
            raise HTTPException(status_code=409, detail=f"Share commitment for trustee {trustee_id} is invalid or has a stale epoch.")
        wallets.append(Web3.to_checksum_address(trustee.wallet_address))
        commitments.append("0x" + share.commitment.lower())
    if len(set(wallets)) != len(wallets):
        raise HTTPException(status_code=422, detail="Two or more trustees use the same wallet address.")
    asset_document = {
        "id": asset.id,
        "policy_id": asset.policy_id,
        "name": asset.name,
        "ciphertext": asset.ciphertext,
        "nonce": asset.nonce,
        "aad": asset.aad,
        "epoch": asset.epoch,
        "threshold": asset.threshold,
    }
    return {
        "asset_id": asset.id,
        "policy_id": policy.id,
        "asset_hash": _canonical_hash(asset_document),
        "epoch": asset.epoch,
        "trustee_wallets": wallets,
        "trustee_ids": trustee_ids,
        "share_commitments": commitments,
        "chain_id": settings.blockchain_chain_id,
        "contract_address": blockchain.contract_address,
        "function_signature": "registerAssetCommitments(string,string,bytes32,uint64,address[],bytes32[])",
    }


@router.get("/registration/assets/{asset_id}")
def get_asset_registration_payload(
    asset_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    asset = db.get(ProtectedAsset, asset_id)
    if asset is None or (user.role != "admin" and asset.owner_user_id != user.id):
        raise HTTPException(status_code=404, detail="Protected asset not found.")
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only the asset owner can register commitments.")
    require_blockchain()
    policy = db.get(Policy, asset.policy_id)
    if policy is None or not policy.active:
        raise HTTPException(status_code=409, detail="The asset policy is missing or inactive.")
    try:
        onchain_policy = blockchain.get_policy(policy.id)
        if not onchain_policy.get("exists"):
            raise HTTPException(status_code=409, detail="Register the policy on-chain before registering its asset commitments.")
        if int(onchain_policy["epoch"]) != asset.epoch:
            raise HTTPException(status_code=409, detail="The asset epoch does not match the on-chain policy epoch.")
        if blockchain.get_asset(asset.id).get("exists"):
            raise HTTPException(status_code=409, detail="This asset's commitments are already registered on-chain.")
        payload = _asset_registration_data(db, asset)
        payload["contract_owner"] = blockchain.contract.functions.owner().call()
        return payload
    except HTTPException:
        raise
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Web3Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to prepare asset commitment registration.") from exc


@router.post("/registration/assets/{asset_id}/verify")
def verify_asset_registration(
    asset_id: str,
    data: TransactionVerificationInput,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    asset = db.get(ProtectedAsset, asset_id)
    if asset is None or (user.role != "admin" and asset.owner_user_id != user.id):
        raise HTTPException(status_code=404, detail="Protected asset not found.")
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only the asset owner can verify commitments.")
    require_blockchain()
    try:
        expected = _asset_registration_data(db, asset)
        tx = blockchain.verify_transaction(data.transaction_hash)
        if not tx.get("found") or not tx.get("mined") or not tx.get("successful") or not tx.get("to_deadrop_contract"):
            raise HTTPException(status_code=409, detail="The supplied transaction is not a successful mined transaction to the configured DeadDrop contract.")
        transaction = blockchain.web3.eth.get_transaction(data.transaction_hash)
        decoded_function, decoded_args = blockchain.contract.decode_function_input(transaction["input"])
        if decoded_function.fn_name != "registerAssetCommitments":
            raise HTTPException(status_code=409, detail="The supplied transaction did not call registerAssetCommitments.")
        submitted_wallets = [Web3.to_checksum_address(item) for item in decoded_args["trusteeWallets"]]
        submitted_commitments = [Web3.to_hex(item).lower() for item in decoded_args["shareCommitments"]]
        if (
            decoded_args["assetId"] != asset_id
            or decoded_args["policyId"] != expected["policy_id"]
            or Web3.to_hex(decoded_args["assetHash"]).lower() != expected["asset_hash"].lower()
            or int(decoded_args["epoch"]) != expected["epoch"]
            or submitted_wallets != expected["trustee_wallets"]
            or submitted_commitments != [item.lower() for item in expected["share_commitments"]]
        ):
            raise HTTPException(status_code=409, detail="The transaction arguments do not match the canonical asset commitment payload.")
        onchain = blockchain.get_asset(asset_id)
        if not onchain["exists"] or onchain["asset_hash"].lower() != expected["asset_hash"].lower() or int(onchain["epoch"]) != expected["epoch"]:
            raise HTTPException(status_code=409, detail="On-chain asset record does not match the protected asset in the database.")
        for wallet, commitment in zip(expected["trustee_wallets"], expected["share_commitments"]):
            actual = blockchain.get_asset_commitment(asset_id, wallet)
            if actual.lower() != commitment.lower():
                raise HTTPException(status_code=409, detail="At least one on-chain share commitment does not match the database.")
        return {"verified": True, "asset_id": asset_id, "transaction": tx, "blockchain": onchain}
    except HTTPException:
        raise
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Web3Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to verify asset commitments on-chain.") from exc


@router.get("/registration/recoveries/{recovery_id}")
def get_recovery_registration_payload(
    recovery_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    recovery = db.get(RecoveryRequest, recovery_id)
    if recovery is None:
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    policy = db.get(Policy, recovery.policy_id)
    if policy is None or not can_access_policy(user, policy, db):
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only the policy owner can register a recovery request.")
    if recovery.status not in {"PENDING", "APPROVED"}:
        raise HTTPException(status_code=409, detail="Only pending or approved recovery requests can be registered.")
    require_blockchain()
    try:
        onchain_policy = blockchain.get_policy(policy.id)
        if not onchain_policy.get("exists"):
            raise HTTPException(status_code=409, detail="Register the policy on-chain first.")
        if blockchain.get_recovery(recovery.id).get("exists"):
            raise HTTPException(status_code=409, detail="This recovery request is already registered on-chain.")
        if (
            int(onchain_policy["version"]) != recovery.policy_version
            or int(onchain_policy["epoch"]) != recovery.policy_epoch
            or not onchain_policy["active"]
        ):
            raise HTTPException(status_code=409, detail="The on-chain policy version/epoch is not synchronized with this recovery request.")
        if recovery.expires_at is None:
            expires_at = (2**64) - 1
        else:
            expires_at = int(recovery.expires_at.replace(tzinfo=timezone.utc).timestamp())
        timelock = int(policy.timelock_seconds or 0)
        latest_block_time = int(blockchain.web3.eth.get_block("latest")["timestamp"])
        if expires_at <= latest_block_time + timelock:
            raise HTTPException(status_code=409, detail="Recovery expiry must be later than the on-chain timelock.")
        return {
            "recovery_id": recovery.id,
            "policy_id": policy.id,
            "incident_hash": Web3.to_hex(Web3.keccak(text=recovery.incident_hash)),
            "expires_at": expires_at,
            "policy_version": recovery.policy_version,
            "policy_epoch": recovery.policy_epoch,
            "timelock_seconds": timelock,
            "chain_id": settings.blockchain_chain_id,
            "contract_address": blockchain.contract_address,
            "function_signature": "requestRecovery(string,string,bytes32,uint64)",
        }
    except HTTPException:
        raise
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Web3Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to prepare the on-chain recovery request.") from exc


@router.post("/registration/recoveries/{recovery_id}/verify")
def verify_recovery_registration(
    recovery_id: str,
    data: TransactionVerificationInput,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    recovery = db.get(RecoveryRequest, recovery_id)
    if recovery is None:
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    policy = db.get(Policy, recovery.policy_id)
    if policy is None or not can_access_policy(user, policy, db):
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only the policy owner can verify this recovery request.")
    require_blockchain()
    try:
        expected_expires_at = (
            (2**64) - 1
            if recovery.expires_at is None
            else int(recovery.expires_at.replace(tzinfo=timezone.utc).timestamp())
        )
        expected = {
            "recovery_id": recovery.id,
            "policy_id": policy.id,
            "incident_hash": Web3.to_hex(Web3.keccak(text=recovery.incident_hash)),
            "expires_at": expected_expires_at,
        }
        tx = blockchain.verify_transaction(data.transaction_hash)
        if not tx.get("found") or not tx.get("mined") or not tx.get("successful") or not tx.get("to_deadrop_contract"):
            raise HTTPException(status_code=409, detail="The supplied transaction is not a successful mined transaction to DeadDrop.")
        transaction = blockchain.web3.eth.get_transaction(data.transaction_hash)
        decoded_function, decoded_args = blockchain.contract.decode_function_input(transaction["input"])
        if decoded_function.fn_name != "requestRecovery":
            raise HTTPException(status_code=409, detail="The supplied transaction did not call requestRecovery.")
        if (
            decoded_args["recoveryId"] != recovery.id
            or decoded_args["policyId"] != policy.id
            or Web3.to_hex(decoded_args["incidentHash"]).lower() != expected["incident_hash"].lower()
            or int(decoded_args["expiresAt"]) != expected["expires_at"]
        ):
            raise HTTPException(status_code=409, detail="Transaction arguments do not match the recovery request.")
        onchain = blockchain.get_recovery(recovery.id)
        if (
            not onchain["exists"]
            or onchain["state"] != "REQUESTED"
            or onchain["incident_hash"].lower() != expected["incident_hash"].lower()
            or int(onchain["policy_version"]) != recovery.policy_version
            or int(onchain["policy_epoch"]) != recovery.policy_epoch
        ):
            raise HTTPException(status_code=409, detail="On-chain recovery state does not match the database request.")
        return {"verified": True, "recovery_id": recovery.id, "transaction": tx, "blockchain": onchain}
    except HTTPException:
        raise
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Web3Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to verify the on-chain recovery request.") from exc


@router.get("/registration/recoveries/{recovery_id}/approvals/{trustee_id}")
def get_trustee_approval_relay_payload(
    recovery_id: str,
    trustee_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    recovery = db.get(RecoveryRequest, recovery_id)
    if recovery is None:
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    policy = db.get(Policy, recovery.policy_id)
    if policy is None or not can_access_policy(user, policy, db):
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    trustee = db.get(Trustee, trustee_id)
    if trustee is None or trustee_id not in set(policy.trustee_ids or []):
        raise HTTPException(status_code=404, detail="Trustee approval not found.")
    if user.role == "trustee" and trustee.user_id != user.id:
        raise HTTPException(status_code=403, detail="You can only relay your own trustee approval.")
    if user.role not in {"trustee", "admin"}:
        raise HTTPException(status_code=403, detail="Only the approving trustee or an administrator can relay this approval.")
    approval = db.scalar(
        select(RecoveryApprovalModel).where(
            RecoveryApprovalModel.recovery_id == recovery_id,
            RecoveryApprovalModel.trustee_id == trustee_id,
        )
    )
    if approval is None:
        raise HTTPException(status_code=404, detail="No verified backend approval exists for this trustee.")
    return {
        "recovery_id": recovery.id,
        "policy_id": policy.id,
        "trustee_id": trustee.id,
        "incident_hash": recovery.incident_hash,
        "signature": approval.signature,
        "policy_version": recovery.policy_version,
        "policy_epoch": recovery.policy_epoch,
    }


@router.get("/registration/recoveries/{recovery_id}/execute")
def get_recovery_execution_payload(
    recovery_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    recovery = db.get(RecoveryRequest, recovery_id)
    if recovery is None:
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    policy = db.get(Policy, recovery.policy_id)
    if policy is None or not can_access_policy(user, policy, db):
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only the policy owner can execute recovery.")
    if recovery.status != "APPROVED":
        raise HTTPException(status_code=409, detail="The database recovery has not reached approval quorum.")
    require_blockchain()
    try:
        onchain_policy = blockchain.get_policy(policy.id)
        onchain_recovery = blockchain.get_recovery(recovery.id)
        if not onchain_policy.get("exists") or not onchain_recovery.get("exists"):
            raise HTTPException(status_code=409, detail="Policy or recovery request is missing on-chain.")
        if onchain_recovery["state"] != "REQUESTED":
            raise HTTPException(status_code=409, detail="On-chain recovery is not pending execution.")
        if int(onchain_recovery["approvals"]) < int(onchain_policy["quorum"]):
            raise HTTPException(status_code=409, detail="On-chain approval quorum has not been reached.")
        now_timestamp = int(blockchain.web3.eth.get_block("latest")["timestamp"])
        if now_timestamp < int(onchain_recovery["execute_after"]):
            raise HTTPException(status_code=409, detail="The on-chain timelock is still active.")
        if now_timestamp >= int(onchain_recovery["expires_at"]):
            raise HTTPException(status_code=410, detail="The on-chain recovery has expired.")
        if (
            int(onchain_policy["version"]) != recovery.policy_version
            or int(onchain_policy["epoch"]) != recovery.policy_epoch
        ):
            raise HTTPException(status_code=409, detail="On-chain policy version or epoch changed.")
        return {
            "recovery_id": recovery.id,
            "chain_id": settings.blockchain_chain_id,
            "contract_address": blockchain.contract_address,
            "approvals": onchain_recovery["approvals"],
            "quorum": onchain_policy["quorum"],
            "execute_after": onchain_recovery["execute_after"],
            "expires_at": onchain_recovery["expires_at"],
            "ready": True,
            "function_signature": "executeRecovery(string,bytes32)",
        }
    except HTTPException:
        raise
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Web3Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to check on-chain recovery execution readiness.") from exc


@router.post("/registration/recoveries/{recovery_id}/execute/verify")
def verify_recovery_execution(
    recovery_id: str,
    data: RecoveryExecutionVerificationInput,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    recovery = db.get(RecoveryRequest, recovery_id)
    if recovery is None:
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    policy = db.get(Policy, recovery.policy_id)
    if policy is None or not can_access_policy(user, policy, db):
        raise HTTPException(status_code=404, detail="Recovery request not found.")
    if user.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only the policy owner can verify recovery execution.")
    require_blockchain()
    try:
        tx = blockchain.verify_transaction(data.transaction_hash)
        if not tx.get("found") or not tx.get("mined") or not tx.get("successful") or not tx.get("to_deadrop_contract"):
            raise HTTPException(status_code=409, detail="The supplied transaction is not a successful mined transaction to DeadDrop.")
        transaction = blockchain.web3.eth.get_transaction(data.transaction_hash)
        decoded_function, decoded_args = blockchain.contract.decode_function_input(transaction["input"])
        if decoded_function.fn_name != "executeRecovery" or decoded_args["recoveryId"] != recovery.id:
            raise HTTPException(status_code=409, detail="The supplied transaction does not execute this recovery request.")
        supplied_artifact_hash = data.artifact_hash.lower()
        if not supplied_artifact_hash.startswith("0x") or len(supplied_artifact_hash) != 66:
            raise HTTPException(status_code=422, detail="Artifact hash must be a 32-byte 0x-prefixed hex value.")
        if Web3.to_hex(decoded_args["artifactHash"]).lower() != supplied_artifact_hash:
            raise HTTPException(status_code=409, detail="Transaction artifact hash does not match the submitted artifact hash.")
        recovery_key = blockchain._id_hash(recovery.id)
        stored_artifact_hash = blockchain.contract.functions.recoveryArtifactHashes(recovery_key).call()
        onchain_recovery = blockchain.get_recovery(recovery.id)
        if onchain_recovery["state"] != "EXECUTED" or Web3.to_hex(stored_artifact_hash).lower() != supplied_artifact_hash:
            raise HTTPException(status_code=409, detail="On-chain recovery execution or artifact hash could not be verified.")
        recovery.status = "EXECUTED"
        recovery.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(recovery)
        return {"verified": True, "recovery_id": recovery.id, "status": recovery.status, "artifact_hash": supplied_artifact_hash, "transaction": tx}
    except HTTPException:
        raise
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Web3Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to verify recovery execution.") from exc
