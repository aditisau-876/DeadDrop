
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import (
    generate_identifier,
    require_roles,
    ensure_owner_or_admin,
)
from app.db.database import get_db
from app.api.policies import ensure_policy_not_registered_onchain
from app.models.asset import ProtectedAsset
from app.models.policy import Policy
from app.models.recovery import RecoveryRequest
from app.models.share import EncryptedShare
from app.models.trustee import Trustee
from app.schemas.share_rotation import (
    ShareRotationRequest,
    ShareRotationResponse,
)
from app.services.recovery_lifecycle import (
    expire_recovery_if_needed,
)
from app.crypto.share_envelope import (
    validate_commitment_format,
    validate_share_envelope,
)
from app.api.blockchain import blockchain, require_blockchain
from app.blockchain.client import Web3
from web3.exceptions import Web3Exception
from app.schemas.share_rotation import OnchainShareRotationFinalizeRequest
from app.services.share_rotation import validate_rotation_request, persist_rotation
from app.models.share_rotation_attempt import ShareRotationAttempt

from app.schemas.share_rotation import (
    OnchainShareRotationReconcileRequest,
)

router = APIRouter(
    prefix="/api/policies",
    tags=["Share Epoch Rotation"],
)


def _normalize_rotation_tx_hash(value: str) -> str:
    value = value.strip().lower()

    if not value.startswith("0x"):
        value = "0x" + value

    if len(value) != 66:
        raise HTTPException(
            status_code=422,
            detail="Invalid transaction hash.",
        )

    try:
        bytes.fromhex(value[2:])
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid transaction hash.",
        ) from exc

    return value


def _rotation_payload_matches(
    stored_payload: dict,
    supplied_payload: dict,
) -> bool:
    return stored_payload == supplied_payload


def _finalize_saved_rotation(
    policy_id: str,
    transaction_hash: str,
    db: Session,
    supplied_payload: dict | None = None,
):
    """
    Verify a successful rotation transaction against the exact
    encrypted payload saved during the prepare step.

    The policy, assets, shares and attempt status are committed
    atomically by persist_rotation().
    """

    normalized_hash = _normalize_rotation_tx_hash(
        transaction_hash
    )

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

    attempt = db.scalar(
        select(ShareRotationAttempt)
        .where(
            ShareRotationAttempt.policy_id == policy_id,
            ShareRotationAttempt.status.in_(
                ["PREPARED", "FINALIZED"]
            ),
        )
        .order_by(ShareRotationAttempt.created_at.desc())
        .with_for_update()
    )

    if attempt is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No saved rotation attempt exists for this policy. "
                "Prepare the rotation before reconciling it."
            ),
        )

    # Idempotent retry: the exact transaction was already finalized.
    if attempt.status == "FINALIZED":
        if attempt.transaction_hash != normalized_hash:
            raise HTTPException(
                status_code=409,
                detail=(
                    "This rotation was already finalized using "
                    "a different transaction hash."
                ),
            )

        return {
            **(attempt.result or {}),
            "verified": True,
            "idempotent": True,
            "transaction_hash": normalized_hash,
            "message": (
                "This rotation was already finalized successfully. "
                "No additional shares or epochs were changed."
            ),
        }

    if supplied_payload is not None and not _rotation_payload_matches(
        attempt.payload,
        supplied_payload,
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "The submitted rotation payload does not match "
                "the payload saved during preparation."
            ),
        )

    rotation_data = ShareRotationRequest.model_validate(
        attempt.payload
    )

    if (
        rotation_data.expected_epoch != attempt.previous_epoch
        or attempt.new_epoch != attempt.previous_epoch + 1
    ):
        raise HTTPException(
            status_code=409,
            detail="The saved rotation attempt has inconsistent epoch values.",
        )

    context = validate_rotation_request(
        db,
        policy_id,
        rotation_data,
    )

    tx = blockchain.verify_transaction(normalized_hash)

    if (
        not tx.get("found")
        or not tx.get("mined")
        or not tx.get("successful")
        or not tx.get("to_deadrop_contract")
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "The supplied transaction is not a successful "
                "mined transaction to the configured DeadDrop contract."
            ),
        )

    transaction = blockchain.web3.eth.get_transaction(
        normalized_hash
    )

    decoded_function, args = (
        blockchain.contract.decode_function_input(
            transaction["input"]
        )
    )

    if decoded_function.fn_name != "rotatePolicyAssetCommitments":
        raise HTTPException(
            status_code=409,
            detail=(
                "The transaction did not call "
                "rotatePolicyAssetCommitments."
            ),
        )

    actual_wallets = [
        Web3.to_checksum_address(item)
        for item in args["trusteeWallets"]
    ]

    actual_matrix = [
        [Web3.to_hex(item).lower() for item in row]
        for row in args["newCommitments"]
    ]

    expected_matrix = [
        [item.lower() for item in row]
        for row in context["commitment_matrix"]
    ]

    if (
        args["policyId"] != policy_id
        or int(args["expectedEpoch"]) != context["previous_epoch"]
        or int(args["newEpoch"]) != context["new_epoch"]
        or list(args["assetIds"]) != context["asset_ids"]
        or actual_wallets != context["trustee_wallets"]
        or actual_matrix != expected_matrix
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "Transaction arguments do not match the "
                "saved and validated rotation payload."
            ),
        )

    onchain_policy = blockchain.get_policy(policy_id)

    if (
        int(onchain_policy["epoch"]) != context["new_epoch"]
        or int(onchain_policy["version"]) != policy.version + 1
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "The on-chain policy epoch/version does not "
                "reflect this rotation."
            ),
        )

    for asset_index, asset_id in enumerate(context["asset_ids"]):
        onchain_asset = blockchain.get_asset(asset_id)

        if (
            not onchain_asset["exists"]
            or int(onchain_asset["epoch"]) != context["new_epoch"]
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"On-chain asset {asset_id} did not "
                    "advance to the new epoch."
                ),
            )

        for trustee_index, wallet in enumerate(
            context["trustee_wallets"]
        ):
            actual = blockchain.get_asset_commitment(
                asset_id,
                wallet,
            ).lower()

            expected = expected_matrix[asset_index][trustee_index]

            if actual != expected:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "On-chain commitment verification failed "
                        f"for asset {asset_id}."
                    ),
                )

    result = persist_rotation(
        db,
        context,
        attempt=attempt,
        transaction_hash=normalized_hash,
    )

    result["verified"] = True
    result["idempotent"] = False
    result["transaction_hash"] = normalized_hash

    return result

@router.post("/{policy_id}/rotate-shares/onchain/prepare")
def prepare_onchain_policy_rotation(
    policy_id: str,
    data: ShareRotationRequest,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    """Validate client-generated shares and return exact wallet transaction arguments."""
    policy = db.get(Policy, policy_id)

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    ensure_owner_or_admin(user, policy.owner_user_id)
    require_blockchain()

    try:
        context = validate_rotation_request(db, policy_id, data)

        onchain_policy = blockchain.get_policy(policy_id)

        if not onchain_policy.get("exists"):
            raise HTTPException(
                status_code=409,
                detail="Register this policy on-chain before using on-chain share rotation.",
            )

        if not onchain_policy.get("active"):
            raise HTTPException(
                status_code=409,
                detail="The on-chain policy is inactive.",
            )

        if int(onchain_policy["epoch"]) != context["previous_epoch"]:
            raise HTTPException(
                status_code=409,
                detail="Database and on-chain policy epochs are not synchronized.",
            )

        if int(onchain_policy["version"]) != int(context["policy"].version):
            raise HTTPException(
                status_code=409,
                detail="Database and on-chain policy versions are not synchronized.",
            )

        policy_key = blockchain._id_hash(policy_id)

        onchain_asset_count = int(
            blockchain.contract.functions.policyAssetCount(
                policy_key
            ).call()
        )

        if onchain_asset_count != len(context["asset_ids"]):
            raise HTTPException(
                status_code=409,
                detail={
                    "message": (
                        "The database asset set does not match the "
                        "on-chain registered asset count. Rotation is blocked."
                    ),
                    "database_asset_count": len(context["asset_ids"]),
                    "onchain_asset_count": onchain_asset_count,
                },
            )

        for asset_id in context["asset_ids"]:
            onchain_asset = blockchain.get_asset(asset_id)

            if (
                not onchain_asset["exists"]
                or onchain_asset["policy_key"].lower()
                != Web3.to_hex(policy_key).lower()
                or int(onchain_asset["epoch"])
                != context["previous_epoch"]
            ):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"On-chain asset {asset_id} is missing, "
                        "belongs to another policy, or has a stale epoch."
                    ),
                )

        # Save the complete rotation payload before validating trustees.
        saved_payload = data.model_dump(mode="json")

        for trustee, wallet in zip(
            context["trustees"],
            context["trustee_wallets"],
        ):
            if not blockchain.is_trustee(policy_id, wallet):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Trustee wallet for {trustee.id} "
                        "is not registered on-chain."
                    ),
                )

        existing_attempt = db.scalar(
            select(ShareRotationAttempt)
            .where(
                ShareRotationAttempt.policy_id == policy_id,
                ShareRotationAttempt.status == "PREPARED",
            )
            .order_by(
                ShareRotationAttempt.created_at.desc()
            )
            .with_for_update()
        )

        if existing_attempt is not None:
            if existing_attempt.payload != saved_payload:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Another prepared rotation already exists "
                        "for this policy. Reconcile it before "
                        "preparing a different rotation."
                    ),
                )

        else:
            attempt = ShareRotationAttempt(
                id=generate_identifier(),
                policy_id=policy_id,
                previous_epoch=context["previous_epoch"],
                new_epoch=context["new_epoch"],
                payload=saved_payload,
                status="PREPARED",
            )

            db.add(attempt)
            db.commit()

        return {
            "policy_id": policy_id,
            "chain_id": blockchain.chain_id,
            "contract_address": blockchain.contract_address,
            "contract_owner": blockchain.contract.functions.owner().call(),
            "previous_epoch": context["previous_epoch"],
            "new_epoch": context["new_epoch"],
            "asset_ids": context["asset_ids"],
            "trustee_wallets": context["trustee_wallets"],
            "new_commitments": context["commitment_matrix"],
            "function_signature": (
                "rotatePolicyAssetCommitments("
                "string,uint64,uint64,string[],address[],bytes32[][])"
            ),
            "message": (
                "Submit this exact function call from the configured "
                "contract-owner wallet, then send the transaction hash "
                "to the finalize endpoint."
            ),
        }

    except HTTPException:
        db.rollback()
        raise

    except (RuntimeError, ValueError) as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    except Web3Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail="Unable to prepare on-chain share rotation.",
        ) from exc
    
@router.post("/{policy_id}/rotate-shares/onchain/finalize")
def finalize_onchain_policy_rotation(
    policy_id: str,
    data: OnchainShareRotationFinalizeRequest,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    """Finalize a saved rotation after verifying its mined transaction."""

    policy = db.get(Policy, policy_id)

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    ensure_owner_or_admin(user, policy.owner_user_id)
    require_blockchain()

    try:
        return _finalize_saved_rotation(
            policy_id=policy_id,
            transaction_hash=data.transaction_hash,
            db=db,
            supplied_payload=None,
        )

    except HTTPException:
        db.rollback()
        raise

    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "The chain rotation succeeded, but database "
                "finalization conflicted with existing share records. "
                "Retry reconciliation using the same transaction hash."
            ),
        ) from exc

    except (RuntimeError, ValueError) as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    except Web3Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail="Unable to verify the on-chain rotation transaction.",
        ) from exc


@router.post(
    "/{policy_id}/rotate-shares",
    response_model=ShareRotationResponse,
)
def rotate_policy_shares(
    policy_id: str,
    data: ShareRotationRequest,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    """
    Re-issue encrypted trustee shares for every protected asset
    under a policy and atomically advance the policy epoch.

    Plaintext keys and shares must be generated and retained
    on the trusted client. The backend only receives encrypted
    share envelopes and commitments.
    """

    # Lock the policy so recovery creation, policy updates,
    # and another rotation cannot concurrently change its state.
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

    ensure_owner_or_admin(user, policy.owner_user_id)
    ensure_policy_not_registered_onchain(policy.id)

    if not policy.active:
        raise HTTPException(
            status_code=409,
            detail="An inactive policy cannot rotate its shares.",
        )

    if policy.epoch != data.expected_epoch:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "The policy epoch has changed.",
                "expected_epoch": data.expected_epoch,
                "current_epoch": policy.epoch,
            },
        )

    previous_epoch = policy.epoch
    new_epoch = previous_epoch + 1

    assigned_trustee_ids = set(policy.trustee_ids or [])

    if len(assigned_trustee_ids) < 2:
        raise HTTPException(
            status_code=409,
            detail="The policy needs at least two assigned trustees.",
        )

    # Lock active recovery requests and expire overdue ones.
    active_recoveries = db.scalars(
        select(RecoveryRequest)
        .where(
            RecoveryRequest.policy_id == policy.id,
            RecoveryRequest.status.in_(["PENDING", "APPROVED"]),
        )
        .with_for_update()
    ).all()

    now = datetime.utcnow()

    for recovery in active_recoveries:
        expire_recovery_if_needed(recovery, now)

    still_active = [
        recovery
        for recovery in active_recoveries
        if recovery.status in {"PENDING", "APPROVED"}
    ]

    if still_active:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "Share rotation is blocked while a recovery request "
                "is pending or approved."
            ),
        )

    # Lock every asset belonging to the policy.
    assets = db.scalars(
        select(ProtectedAsset)
        .where(ProtectedAsset.policy_id == policy.id)
        .order_by(ProtectedAsset.id)
        .with_for_update()
    ).all()

    if not assets:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="This policy has no protected assets to rotate.",
        )

    actual_asset_ids = {asset.id for asset in assets}
    supplied_asset_ids = [
        item.asset_id for item in data.assets
    ]

    if len(supplied_asset_ids) != len(set(supplied_asset_ids)):
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail="Duplicate asset IDs are not allowed.",
        )

    if set(supplied_asset_ids) != actual_asset_ids:
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail={
                "message": (
                    "Every protected asset under this policy must "
                    "be included exactly once."
                ),
                "missing_asset_ids": sorted(
                    actual_asset_ids - set(supplied_asset_ids)
                ),
                "unexpected_asset_ids": sorted(
                    set(supplied_asset_ids) - actual_asset_ids
                ),
            },
        )

    # All assets must currently be in the same policy epoch.
    wrong_epoch_assets = [
        asset.id
        for asset in assets
        if asset.epoch != previous_epoch
    ]

    if wrong_epoch_assets:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "Some assets are not synchronized with "
                    "the current policy epoch."
                ),
                "asset_ids": wrong_epoch_assets,
                "policy_epoch": previous_epoch,
            },
        )

    # Load and lock all assigned trustees.
    trustees = db.scalars(
        select(Trustee)
        .where(Trustee.id.in_(assigned_trustee_ids))
        .order_by(Trustee.id)
        .with_for_update()
    ).all()

    trustees_by_id = {
        trustee.id: trustee
        for trustee in trustees
    }

    if set(trustees_by_id) != assigned_trustee_ids:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="One or more assigned trustees no longer exist.",
        )

    inactive_trustees = [
        trustee.id
        for trustee in trustees
        if not trustee.active
    ]

    if inactive_trustees:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "All assigned trustees must be active "
                    "before share rotation."
                ),
                "inactive_trustee_ids": inactive_trustees,
            },
        )

    trustees_without_keys = [
        trustee.id
        for trustee in trustees
        if not trustee.public_key
    ]

    if trustees_without_keys:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "Every assigned trustee must have a registered "
                    "encryption public key."
                ),
                "trustee_ids": trustees_without_keys,
            },
        )

    # Validate every new encrypted share before writing anything.
    pending_shares: list[EncryptedShare] = []

    for asset_input in data.assets:
        asset = next(
            item
            for item in assets
            if item.id == asset_input.asset_id
        )

        supplied_trustee_ids = [
            item.trustee_id
            for item in asset_input.shares
        ]

        if len(supplied_trustee_ids) != len(
            set(supplied_trustee_ids)
        ):
            db.rollback()
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Duplicate trustee shares are not allowed.",
                    "asset_id": asset.id,
                },
            )

        if set(supplied_trustee_ids) != assigned_trustee_ids:
            db.rollback()
            raise HTTPException(
                status_code=422,
                detail={
                    "message": (
                        "Every asset must have exactly one new share "
                        "for each assigned trustee."
                    ),
                    "asset_id": asset.id,
                    "missing_trustees": sorted(
                        assigned_trustee_ids - set(supplied_trustee_ids)
                    ),
                    "unexpected_trustees": sorted(
                        set(supplied_trustee_ids) - assigned_trustee_ids
                    ),
                },
            )

        for share_input in asset_input.shares:
            trustee_id = share_input.trustee_id

            if not validate_commitment_format(
                share_input.commitment
            ):
                db.rollback()
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "Invalid share commitment format.",
                        "asset_id": asset.id,
                        "trustee_id": trustee_id,
                    },
                )

            valid, reason = validate_share_envelope(
                share_input.encrypted_share,
                expected_policy_id=policy.id,
                expected_trustee_id=trustee_id,
                expected_epoch=new_epoch,
            )

            if not valid:
                db.rollback()
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "Invalid new encrypted share envelope.",
                        "asset_id": asset.id,
                        "trustee_id": trustee_id,
                        "reason": reason,
                    },
                )

            pending_shares.append(
                EncryptedShare(
                    id=generate_identifier(),
                    asset_id=asset.id,
                    trustee_id=trustee_id,
                    encrypted_share=share_input.encrypted_share,
                    commitment=share_input.commitment.lower(),
                    epoch=new_epoch,
                )
            )

    try:
        # The database unique constraint provides an additional
        # safeguard against duplicate asset/trustee/epoch records.
        db.add_all(pending_shares)

        # Move every asset and the policy to the new epoch together.
        for asset in assets:
            asset.epoch = new_epoch

        policy.epoch = new_epoch
        policy.version += 1

        db.commit()

    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "Share rotation conflicted with an existing epoch "
                "or another database constraint."
            ),
        ) from exc

    except Exception:
        db.rollback()
        raise

    return ShareRotationResponse(
        policy_id=policy.id,
        previous_epoch=previous_epoch,
        new_epoch=new_epoch,
        new_policy_version=policy.version,
        updated_asset_count=len(assets),
        inserted_share_count=len(pending_shares),
        message=(
            "Share rotation completed. New encrypted shares are "
            "stored and the policy and all protected assets now use "
            "the new epoch. Previous epoch records were retained."
        ),
    )

@router.post("/{policy_id}/rotate-shares/onchain/reconcile")
def reconcile_onchain_policy_rotation(
    policy_id: str,
    data: OnchainShareRotationReconcileRequest,
    db: Session = Depends(get_db),
    user=Depends(require_roles("owner", "admin")),
):
    """
    Recover a prepared rotation using only its blockchain transaction hash.

    The encrypted payload is loaded from the saved database attempt.
    """

    policy = db.get(Policy, policy_id)

    if policy is None:
        raise HTTPException(
            status_code=404,
            detail="Policy not found.",
        )

    ensure_owner_or_admin(user, policy.owner_user_id)
    require_blockchain()

    try:
        return _finalize_saved_rotation(
            policy_id=policy_id,
            transaction_hash=data.transaction_hash,
            db=db,
        )

    except HTTPException:
        db.rollback()
        raise

    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "Database finalization conflicted with existing "
                "share records. Retry using the same transaction hash."
            ),
        ) from exc

    except (RuntimeError, ValueError) as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    except Web3Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail="Unable to reconcile the on-chain rotation.",
        ) from exc
