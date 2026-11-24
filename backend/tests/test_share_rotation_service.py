
from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (
    AuditLog,
    BlockchainEvent,
    BlockchainRecoveryProjection,
    BlockchainSyncCheckpoint,
    EncryptedShare,
    Policy,
    ProtectedAsset,
    RecoveryApproval,
    RecoveryRequest,
    ShareReleaseChallenge,
    Trustee,
    User,
)
from app.db.database import Base
from app.crypto.recovery import prepare_recovery_material
from app.crypto.share_encryption import generate_trustee_key_pair
from app.schemas.share_rotation import (
    AssetShareRotation,
    RotatedShareInput,
    ShareRotationRequest,
)
from app.services.share_rotation import (
    persist_rotation,
    validate_rotation_request,
)


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    session = TestingSession()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def make_rotation_fixture(db):
    policy_id = "rotation-policy-test"

    trustee_ids = [
        "rotation-trustee-a",
        "rotation-trustee-b",
        "rotation-trustee-c",
    ]

    trustees_for_crypto = []

    for index, trustee_id in enumerate(trustee_ids, start=1):
        key_pair = generate_trustee_key_pair()

        trustees_for_crypto.append({
            "id": trustee_id,
            "public_key": key_pair.public_key,
        })

        db.add(
            Trustee(
                id=trustee_id,
                name=f"Trustee {index}",
                role="trustee",
                wallet_address=f"0x{index:040x}",
                public_key=key_pair.public_key,
                active=True,
            )
        )

    db.add(
        Policy(
            id=policy_id,
            owner_user_id=None,
            name="Rotation Test Policy",
            description="Isolated share rotation service test",
            policy_expression="2 of 3 trustees",
            policy_tree=None,
            trustee_ids=trustee_ids,
            version=1,
            epoch=1,
            active=True,
        )
    )

    asset_ids = [
        "rotation-asset-a",
        "rotation-asset-b",
    ]

    for index, asset_id in enumerate(asset_ids, start=1):
        db.add(
            ProtectedAsset(
                id=asset_id,
                owner_user_id=None,
                policy_id=policy_id,
                name=f"Protected asset {index}",
                description=None,
                ciphertext="test-ciphertext",
                nonce="dGVzdC1ub25jZQ==",
                aad=None,
                epoch=1,
                threshold=2,
            )
        )

    db.flush()

    # Seed old epoch shares. These must remain after rotation.
    for asset_id in asset_ids:
        old_material = prepare_recovery_material(
            f"old-secret-{asset_id}x".encode(),
            threshold=2,
            trustees=trustees_for_crypto,
            policy_id=policy_id,
            epoch=1,
        )

        for share in old_material.shares:
            db.add(
                EncryptedShare(
                    id=f"old-{asset_id}-{share.trustee_id}",
                    asset_id=asset_id,
                    trustee_id=share.trustee_id,
                    encrypted_share=share.encrypted_share,
                    commitment=share.commitment,
                    epoch=1,
                )
            )

    db.commit()

    return (
        policy_id,
        trustee_ids,
        trustees_for_crypto,
        asset_ids,
    )


def build_rotation_request(
    policy_id,
    trustees_for_crypto,
    asset_ids,
):
    assets = []

    for asset_id in asset_ids:
        new_material = prepare_recovery_material(
            f"new-secret-{asset_id}x".encode(),
            threshold=2,
            trustees=trustees_for_crypto,
            policy_id=policy_id,
            epoch=2,
        )

        assets.append(
            AssetShareRotation(
                asset_id=asset_id,
                shares=[
                    RotatedShareInput(
                        trustee_id=share.trustee_id,
                        encrypted_share=share.encrypted_share,
                        commitment=share.commitment,
                    )
                    for share in new_material.shares
                ],
            )
        )

    return ShareRotationRequest(
        expected_epoch=1,
        assets=assets,
    )


def test_rotation_validation_accepts_complete_asset_and_trustee_matrix(
    db_session,
):
    (
        policy_id,
        trustee_ids,
        trustees_for_crypto,
        asset_ids,
    ) = make_rotation_fixture(db_session)

    request = build_rotation_request(
        policy_id,
        trustees_for_crypto,
        asset_ids,
    )

    context = validate_rotation_request(
        db_session,
        policy_id,
        request,
    )

    assert context["previous_epoch"] == 1
    assert context["new_epoch"] == 2
    assert context["asset_ids"] == sorted(asset_ids)

    assert [
        trustee.id for trustee in context["trustees"]
    ] == trustee_ids

    assert len(context["pending_shares"]) == (
        len(asset_ids) * len(trustee_ids)
    )

    assert len(context["commitment_matrix"]) == len(asset_ids)

    assert all(
        len(row) == len(trustee_ids)
        for row in context["commitment_matrix"]
    )


def test_rotation_rejects_request_that_omits_a_protected_asset(
    db_session,
):
    (
        policy_id,
        _,
        trustees_for_crypto,
        asset_ids,
    ) = make_rotation_fixture(db_session)

    request = build_rotation_request(
        policy_id,
        trustees_for_crypto,
        asset_ids[:1],
    )

    with pytest.raises(HTTPException) as error:
        validate_rotation_request(
            db_session,
            policy_id,
            request,
        )

    assert error.value.status_code == 422
    assert "missing_asset_ids" in str(error.value.detail)


def test_rotation_rejects_asset_with_missing_trustee_share(
    db_session,
):
    (
        policy_id,
        trustee_ids,
        trustees_for_crypto,
        asset_ids,
    ) = make_rotation_fixture(db_session)

    request = build_rotation_request(
        policy_id,
        trustees_for_crypto,
        asset_ids,
    )

    first_asset = request.assets[0]

    request.assets[0] = AssetShareRotation(
        asset_id=first_asset.asset_id,
        shares=[
            share
            for share in first_asset.shares
            if share.trustee_id != trustee_ids[-1]
        ],
    )

    with pytest.raises(HTTPException) as error:
        validate_rotation_request(
            db_session,
            policy_id,
            request,
        )

    assert error.value.status_code == 422
    assert "missing_trustees" in str(error.value.detail)


def test_persist_rotation_advances_all_epochs_and_retains_old_shares(
    db_session,
):
    (
        policy_id,
        trustee_ids,
        trustees_for_crypto,
        asset_ids,
    ) = make_rotation_fixture(db_session)

    request = build_rotation_request(
        policy_id,
        trustees_for_crypto,
        asset_ids,
    )

    context = validate_rotation_request(
        db_session,
        policy_id,
        request,
    )

    result = persist_rotation(
        db_session,
        context,
    )

    policy = db_session.get(Policy, policy_id)

    assets = db_session.scalars(
        select(ProtectedAsset).where(
            ProtectedAsset.policy_id == policy_id
        )
    ).all()

    old_share_count = db_session.scalar(
        select(func.count(EncryptedShare.id)).where(
            EncryptedShare.epoch == 1
        )
    )

    new_share_count = db_session.scalar(
        select(func.count(EncryptedShare.id)).where(
            EncryptedShare.epoch == 2
        )
    )

    assert result["previous_epoch"] == 1
    assert result["new_epoch"] == 2

    assert result["updated_asset_count"] == len(asset_ids)

    assert result["inserted_share_count"] == (
        len(asset_ids) * len(trustee_ids)
    )

    assert policy.epoch == 2
    assert policy.version == 2

    assert {asset.epoch for asset in assets} == {2}

    # Historical encrypted shares must still exist.
    assert old_share_count == len(asset_ids) * len(trustee_ids)

    assert new_share_count == len(asset_ids) * len(trustee_ids)


def test_rotation_rejects_stale_expected_epoch(db_session):
    (
        policy_id,
        _,
        trustees_for_crypto,
        asset_ids,
    ) = make_rotation_fixture(db_session)

    request = build_rotation_request(
        policy_id,
        trustees_for_crypto,
        asset_ids,
    )

    request.expected_epoch = 2

    with pytest.raises(HTTPException) as error:
        validate_rotation_request(
            db_session,
            policy_id,
            request,
        )

    assert error.value.status_code == 409
    assert "epoch" in str(error.value.detail).lower()
