
from __future__ import annotations

import hashlib
import secrets

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.crypto.share_envelope import (
    validate_commitment_format,
    validate_share_envelope,
)
from app.crypto.signatures import (
    build_share_release_typed_data,
    verify_share_release_signature,
)
from app.db.database import get_db
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

    if recovery.status != "APPROVED":
        raise HTTPException(
            status_code=409,
            detail="Governance approval is not complete.",
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
