
import pytest

from app.crypto.recovery import prepare_recovery_material
from app.crypto.share_encryption import generate_trustee_key_pair
from app.crypto.share_envelope import validate_share_envelope
from app.crypto.share_verification import decrypt_and_verify_share


def build_trustees():
    trustees = []
    private_keys = {}

    for index in range(3):
        trustee_id = f"rotation-trustee-{index + 1}"
        key_pair = generate_trustee_key_pair()

        trustees.append({
            "id": trustee_id,
            "public_key": key_pair.public_key,
        })

        private_keys[trustee_id] = key_pair.private_key

    return trustees, private_keys


def test_new_epoch_generates_valid_encrypted_shares():
    secret = b"DeadDrop-epoch-rotation-test-key"
    trustees, _ = build_trustees()

    material = prepare_recovery_material(
        secret,
        threshold=2,
        trustees=trustees,
        policy_id="rotation-policy",
        epoch=2,
    )

    assert len(material.shares) == 3

    for share in material.shares:
        assert share.epoch == 2

        valid, reason = validate_share_envelope(
            share.encrypted_share,
            expected_policy_id="rotation-policy",
            expected_trustee_id=share.trustee_id,
            expected_epoch=2,
        )

        assert valid, reason


def test_old_epoch_share_is_rejected_for_new_epoch():
    secret = b"DeadDrop-epoch-rotation-test-key"
    trustees, _ = build_trustees()

    old_material = prepare_recovery_material(
        secret,
        threshold=2,
        trustees=trustees,
        policy_id="rotation-policy",
        epoch=1,
    )

    old_share = old_material.shares[0]

    valid, reason = validate_share_envelope(
        old_share.encrypted_share,
        expected_policy_id="rotation-policy",
        expected_trustee_id=old_share.trustee_id,
        expected_epoch=2,
    )

    assert not valid
    assert "epoch" in reason.lower()


def test_new_epoch_share_can_be_decrypted_and_verified():
    secret = b"DeadDrop-epoch-rotation-test-key"
    trustees, private_keys = build_trustees()

    material = prepare_recovery_material(
        secret,
        threshold=2,
        trustees=trustees,
        policy_id="rotation-policy",
        epoch=2,
    )

    prepared_share = material.shares[0]

    verified = decrypt_and_verify_share(
        prepared_share.encrypted_share,
        trustee_private_key=private_keys[prepared_share.trustee_id],
        expected_commitment=prepared_share.commitment,
        expected_policy_id="rotation-policy",
        expected_trustee_id=prepared_share.trustee_id,
        expected_epoch=2,
    )

    assert verified.trustee_id == prepared_share.trustee_id
    assert verified.epoch == 2
    assert verified.policy_id == "rotation-policy"
    assert verified.value


def test_old_and_new_epoch_commitments_are_different():
    secret = b"DeadDrop-epoch-rotation-test-key"
    trustees, _ = build_trustees()

    old_material = prepare_recovery_material(
        secret,
        threshold=2,
        trustees=trustees,
        policy_id="rotation-policy",
        epoch=1,
    )

    new_material = prepare_recovery_material(
        secret,
        threshold=2,
        trustees=trustees,
        policy_id="rotation-policy",
        epoch=2,
    )

    old_commitments = {
        share.trustee_id: share.commitment
        for share in old_material.shares
    }

    new_commitments = {
        share.trustee_id: share.commitment
        for share in new_material.shares
    }

    for trustee_id in old_commitments:
        assert old_commitments[trustee_id] != new_commitments[trustee_id]
