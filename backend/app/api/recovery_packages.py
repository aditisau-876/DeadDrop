
from __future__ import annotations

import hashlib
import secrets

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from web3 import Web3

from app.crypto.share_envelope import (
    validate_commitment_format,
    validate_share_envelope,
)
from app.crypto.signatures import (
    build_share_release_typed_data,
    verify_share_release_signature,
)
from app.db.database import get_db
from app.api.blockchain import blockchain as chain_client
from app.models.asset import ProtectedAsset
from app.models.policy import Policy
from app.models.recovery import (
    RecoveryRequest,
    ShareReleaseChallenge,
)
from app.models.share import EncryptedShare
from app.models.trustee import Trustee
from app.schemas.recovery_package import (
    ShareReleaseChallengeRequest,
    ShareReleaseChallengeResponse,
    ShareReleaseRequest,
    ShareReleaseResponse,
)
from app.core.security import generate_identifier, get_current_user, require_roles
from app.services.recovery_lifecycle import (
    expire_recovery_if_needed,
    recovery_release_block_reason,
)

router = APIRouter(
    prefix="/api/recovery-packages",
    dependencies=[Depends(get_current_user)],
    tags=["Recovery Packages"],
)

CHALLENGE_TTL_SECONDS = 300


def get_release_context(
    *,
    recovery_id: str,
    asset_id: str,
    trustee_id: str,
    db: Session,
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

    if expire_recovery_if_needed(recovery):
        db.commit()

    release_block_reason = recovery_release_block_reason(
        recovery
    )

    if recovery.status == "EXPIRED":
        db.commit()

    if release_block_reason:
        raise HTTPException(
            status_code=409,
            detail=release_block_reason,
        )

    policy = db.get(
        Policy,
        recovery.policy_id,
    )

    if policy is None or not policy.active:
        raise HTTPException(
            status_code=409,
            detail="Policy is unavailable or inactive.",
        )

    if (
        policy.version != recovery.policy_version
        or policy.epoch != recovery.policy_epoch
    ):
        raise HTTPException(
            status_code=409,
            detail="Policy changed after recovery was requested.",
        )

    asset = db.get(
        ProtectedAsset,
        asset_id,
    )

    if asset is None:
        raise HTTPException(
            status_code=404,
            detail="Protected asset not found.",
        )

    if asset.policy_id != policy.id:
        raise HTTPException(
            status_code=403,
            detail="Asset does not belong to this policy.",
        )

    if (
        asset.epoch != policy.epoch
        or asset.epoch != recovery.policy_epoch
    ):
        raise HTTPException(
            status_code=409,
            detail="Asset epoch does not match recovery epoch.",
        )

    trustee = db.get(
        Trustee,
        trustee_id,
    )

    if trustee is None or not trustee.active:
        raise HTTPException(
            status_code=403,
            detail="Trustee is missing or inactive.",
        )

    if trustee.id not in set(policy.trustee_ids or []):
        raise HTTPException(
            status_code=403,
            detail="Trustee is not assigned to this policy.",
        )

    if not trustee.wallet_address:
        raise HTTPException(
            status_code=409,
            detail="Trustee has no registered wallet.",
        )

    share = db.scalar(
        select(EncryptedShare).where(
            EncryptedShare.asset_id == asset.id,
            EncryptedShare.trustee_id == trustee.id,
            EncryptedShare.epoch == asset.epoch,
        )
    )

    if share is None:
        raise HTTPException(
            status_code=404,
            detail="Encrypted share not found.",
        )

    if not validate_commitment_format(share.commitment):
        raise HTTPException(
            status_code=422,
            detail="Stored commitment format is invalid.",
        )

    valid, reason = validate_share_envelope(
        share.encrypted_share,
        expected_policy_id=policy.id,
        expected_trustee_id=trustee.id,
        expected_epoch=asset.epoch,
    )

    if not valid:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Stored share envelope is invalid.",
                "reason": reason,
            },
        )

    # Verify the release conditions against the actual contract.
    try:
        chain_client._require_contract()

        chain_policy = chain_client.get_policy(policy.id)
        chain_recovery = chain_client.get_recovery(recovery.id)
        chain_asset = chain_client.get_asset(asset.id)

        if (
            not chain_policy.get("exists")
            or not chain_recovery.get("exists")
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "Policy or recovery request is not "
                    "registered on-chain."
                ),
            )

        if chain_recovery["state"] != "REQUESTED":
            raise HTTPException(
                status_code=409,
                detail=(
                    "On-chain recovery is not in the "
                    "requested state."
                ),
            )

        if (
            int(chain_policy["version"]) != recovery.policy_version
            or int(chain_policy["epoch"]) != recovery.policy_epoch
            or int(chain_recovery["policy_version"])
            != recovery.policy_version
            or int(chain_recovery["policy_epoch"])
            != recovery.policy_epoch
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "On-chain policy version or epoch does "
                    "not match the recovery request."
                ),
            )

        if (
            int(recovery.required_approvals)
            != int(chain_policy["quorum"])
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "Database and on-chain recovery quorum "
                    "values do not match."
                ),
            )

        if (
            int(chain_recovery["approvals"])
            < int(chain_policy["quorum"])
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "The on-chain trustee approval quorum "
                    "has not been reached."
                ),
            )

        # NEW: The specific trustee must be registered on-chain.
        if not chain_client.is_trustee(
            policy.id,
            trustee.wallet_address,
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    "This trustee wallet is not registered "
                    "for the policy on-chain."
                ),
            )

        # NEW: Overall quorum is not enough. This trustee must
        # personally have an approval recorded on-chain.
        if not chain_client.has_approved(
            recovery.id,
            trustee.wallet_address,
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    "This trustee has not personally approved "
                    "this recovery on-chain and cannot receive "
                    "its encrypted share."
                ),
            )

        now_timestamp = int(
            chain_client.web3.eth.get_block("latest")["timestamp"]
        )

        if now_timestamp < int(chain_recovery["execute_after"]):
            raise HTTPException(
                status_code=409,
                detail="The on-chain recovery timelock is still active.",
            )

        if now_timestamp >= int(chain_recovery["expires_at"]):
            raise HTTPException(
                status_code=410,
                detail="The on-chain recovery request has expired.",
            )

        expected_policy_key = Web3.to_hex(
            chain_client._id_hash(policy.id)
        ).lower()

        if (
            not chain_asset.get("exists")
            or int(chain_asset["epoch"]) != asset.epoch
            or chain_asset["policy_key"].lower()
            != expected_policy_key
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "Protected asset commitments are not registered "
                    "for the current policy epoch."
                ),
            )

        onchain_commitment = chain_client.get_asset_commitment(
            asset.id,
            trustee.wallet_address,
        )

        if (
            onchain_commitment.lower()
            != ("0x" + share.commitment.lower())
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "The trustee share commitment does not match "
                    "the on-chain asset commitment."
                ),
            )

    except HTTPException:
        raise

    except (RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    return recovery, policy, asset, trustee, share



@router.post(
    "/challenge",
    response_model=ShareReleaseChallengeResponse,
)
def create_share_release_challenge(
    data: ShareReleaseChallengeRequest,
    db: Session = Depends(get_db),
    user = Depends(require_roles("trustee", "admin")),
):
    recovery, policy, asset, trustee, _ = get_release_context(
        recovery_id=data.recovery_id,
        asset_id=data.asset_id,
        trustee_id=data.trustee_id,
        db=db,
    )

    if user.role == "trustee" and trustee.user_id != user.id:
        raise HTTPException(status_code=403, detail="This account is not linked to the requested trustee.")

    now = datetime.utcnow()

    challenge_id = generate_identifier()
    nonce = secrets.token_urlsafe(32)

    nonce_hash = hashlib.sha256(
        nonce.encode("utf-8")
    ).hexdigest()

    expires_at = now + timedelta(
        seconds=CHALLENGE_TTL_SECONDS
    )

    challenge = ShareReleaseChallenge(
        id=challenge_id,
        recovery_id=recovery.id,
        asset_id=asset.id,
        trustee_id=trustee.id,
        nonce_hash=nonce_hash,
        policy_version=policy.version,
        policy_epoch=policy.epoch,
        expires_at=expires_at,
        consumed_at=None,
    )

    db.add(challenge)
    db.commit()

    typed_data = build_share_release_typed_data(
        challenge_id=challenge_id,
        nonce=nonce,
        recovery_id=recovery.id,
        asset_id=asset.id,
        policy_id=policy.id,
        trustee_id=trustee.id,
        policy_version=policy.version,
        epoch=asset.epoch,
    )

    return ShareReleaseChallengeResponse(
        challenge_id=challenge_id,
        expires_at=expires_at.isoformat(),
        typed_data=typed_data,
    )


@router.post(
    "/release",
    response_model=ShareReleaseResponse,
)
def release_encrypted_share(
    data: ShareReleaseRequest,
    db: Session = Depends(get_db),
    user = Depends(require_roles("trustee", "admin")),
):
    recovery, policy, asset, trustee, share = get_release_context(
        recovery_id=data.recovery_id,
        asset_id=data.asset_id,
        trustee_id=data.trustee_id,
        db=db,
    )

    if user.role == "trustee" and trustee.user_id != user.id:
        raise HTTPException(status_code=403, detail="This account is not linked to the requested trustee.")

    challenge = db.get(
        ShareReleaseChallenge,
        data.challenge_id,
    )

    if challenge is None:
        raise HTTPException(
            status_code=404,
            detail="Share-release challenge not found.",
        )

    if (
        challenge.recovery_id != recovery.id
        or challenge.asset_id != asset.id
        or challenge.trustee_id != trustee.id
    ):
        raise HTTPException(
            status_code=403,
            detail="Challenge does not match this release request.",
        )

    now = datetime.utcnow()

    if (
        challenge.policy_version != policy.version
        or challenge.policy_epoch != policy.epoch
    ):
        raise HTTPException(
            status_code=409,
            detail="Policy changed after the release challenge was issued.",
        )

    if challenge.consumed_at is not None:
        raise HTTPException(
            status_code=409,
            detail="This challenge has already been used.",
        )

    if challenge.expires_at <= now:
        raise HTTPException(
            status_code=410,
            detail="Share-release challenge has expired.",
        )

    supplied_nonce_hash = hashlib.sha256(
        data.nonce.encode("utf-8")
    ).hexdigest()

    if not secrets.compare_digest(
        supplied_nonce_hash,
        challenge.nonce_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid challenge nonce.",
        )

    valid_signature = verify_share_release_signature(
        signature=data.signature,
        expected_wallet=trustee.wallet_address or "",
        challenge_id=challenge.id,
        nonce=data.nonce,
        recovery_id=recovery.id,
        asset_id=asset.id,
        policy_id=policy.id,
        trustee_id=trustee.id,
        policy_version=policy.version,
        epoch=asset.epoch,
    )

    if not valid_signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid share-release signature.",
        )

    # Atomic one-time consumption. If two requests race,
    # only one can change consumed_at from NULL.
    result = db.execute(
        update(ShareReleaseChallenge)
        .where(
            ShareReleaseChallenge.id == challenge.id,
            ShareReleaseChallenge.consumed_at.is_(None),
            ShareReleaseChallenge.expires_at > now,
            ShareReleaseChallenge.nonce_hash == supplied_nonce_hash,
        )
        .values(consumed_at=now)
    )

    if result.rowcount != 1:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail=(
                "Challenge was already consumed or has expired."
            ),
        )

    db.commit()

    return ShareReleaseResponse(
        recovery_id=recovery.id,
        asset_id=asset.id,
        policy_id=policy.id,
        trustee_id=trustee.id,
        epoch=share.epoch,
        encrypted_share=share.encrypted_share,
        commitment=share.commitment,
        message=(
            "Encrypted share released after one-time challenge "
            "and trustee signature verification. Decryption and "
            "reconstruction remain client-side."
        ),
    )
