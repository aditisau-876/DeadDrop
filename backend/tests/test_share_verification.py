
from dataclasses import replace
import base64

import pytest

from app.crypto.encryption import encrypt
from app.crypto.recovery import prepare_recovery_material
from app.crypto.share_verification import (
    decrypt_and_verify_share,
    recover_and_decrypt_asset,
    reconstruct_verified_secret,
)
from app.crypto.share_encryption import generate_trustee_key_pair


def create_test_material():
    policy_id = "policy-verification-test"
    epoch = 1
    threshold = 3

    plaintext = b"DeadDrop verified recovery payload."

    trustees = []
    key_pairs = {}

    for index in range(5):
        trustee_id = f"trustee-{index + 1}"
        key_pair = generate_trustee_key_pair()

        trustees.append({
            "id": trustee_id,
            "public_key": key_pair.public_key,
        })

        key_pairs[trustee_id] = key_pair

    # Create the actual protected payload with a fresh AES key.
    from app.crypto.encryption import generate_key

    encryption_key = generate_key()

    encrypted_payload = encrypt(
        plaintext,
        encryption_key,
        associated_data=f"asset:{policy_id}".encode(),
    )

    recovery_material = prepare_recovery_material(
        encryption_key,
        threshold=threshold,
        trustees=trustees,
        policy_id=policy_id,
        epoch=epoch,
    )

    return {
        "policy_id": policy_id,
        "epoch": epoch,
        "threshold": threshold,
        "plaintext": plaintext,
        "payload": encrypted_payload,
        "shares": recovery_material.shares,
        "key_pairs": key_pairs,
    }


def decrypt_test_shares(material, count=3):
    verified_shares = []

    for prepared_share in material["shares"][:count]:
        trustee_id = prepared_share.trustee_id

        verified = decrypt_and_verify_share(
            prepared_share.encrypted_share,
            trustee_private_key=material["key_pairs"][trustee_id].private_key,
            expected_commitment=prepared_share.commitment,
            expected_policy_id=material["policy_id"],
            expected_trustee_id=trustee_id,
            expected_epoch=material["epoch"],
        )

        verified_shares.append(verified)

    return verified_shares


def test_complete_verified_recovery_flow():
    material = create_test_material()

    verified_shares = decrypt_test_shares(material)

    recovered = recover_and_decrypt_asset(
        verified_shares,
        threshold=material["threshold"],
        expected_policy_id=material["policy_id"],
        expected_epoch=material["epoch"],
        payload=material["payload"],
    )

    assert recovered == material["plaintext"]


def test_invalid_commitment_is_rejected():
    material = create_test_material()
    prepared_share = material["shares"][0]
    trustee_id = prepared_share.trustee_id

    with pytest.raises(ValueError, match="commitment verification failed"):
        decrypt_and_verify_share(
            prepared_share.encrypted_share,
            trustee_private_key=material["key_pairs"][trustee_id].private_key,
            expected_commitment="a" * 64,
            expected_policy_id=material["policy_id"],
            expected_trustee_id=trustee_id,
            expected_epoch=material["epoch"],
        )


def test_wrong_policy_is_rejected():
    material = create_test_material()
    prepared_share = material["shares"][0]
    trustee_id = prepared_share.trustee_id

    with pytest.raises(ValueError, match="envelope rejected"):
        decrypt_and_verify_share(
            prepared_share.encrypted_share,
            trustee_private_key=material["key_pairs"][trustee_id].private_key,
            expected_commitment=prepared_share.commitment,
            expected_policy_id="different-policy",
            expected_trustee_id=trustee_id,
            expected_epoch=material["epoch"],
        )


def test_wrong_epoch_is_rejected():
    material = create_test_material()
    prepared_share = material["shares"][0]
    trustee_id = prepared_share.trustee_id

    with pytest.raises(ValueError, match="envelope rejected"):
        decrypt_and_verify_share(
            prepared_share.encrypted_share,
            trustee_private_key=material["key_pairs"][trustee_id].private_key,
            expected_commitment=prepared_share.commitment,
            expected_policy_id=material["policy_id"],
            expected_trustee_id=trustee_id,
            expected_epoch=material["epoch"] + 1,
        )


def test_duplicate_trustee_shares_are_rejected():
    material = create_test_material()
    verified_shares = decrypt_test_shares(material)

    duplicate_shares = [
        verified_shares[0],
        verified_shares[0],
        verified_shares[1],
    ]

    with pytest.raises(ValueError, match="Duplicate trustee"):
        reconstruct_verified_secret(
            duplicate_shares,
            threshold=3,
            expected_policy_id=material["policy_id"],
            expected_epoch=material["epoch"],
        )


def test_insufficient_verified_shares_are_rejected():
    material = create_test_material()
    verified_shares = decrypt_test_shares(material, count=2)

    with pytest.raises(ValueError, match="Not enough verified shares"):
        reconstruct_verified_secret(
            verified_shares,
            threshold=3,
            expected_policy_id=material["policy_id"],
            expected_epoch=material["epoch"],
        )


def test_modified_payload_fails_aes_gcm_authentication():
    material = create_test_material()
    verified_shares = decrypt_test_shares(material)

    modified_payload = replace(
        material["payload"],
        ciphertext=base64.b64encode(
            b"modified encrypted payload"
        ).decode("ascii"),
    )

    with pytest.raises(ValueError, match="Asset authentication failed"):
        recover_and_decrypt_asset(
            verified_shares,
            threshold=material["threshold"],
            expected_policy_id=material["policy_id"],
            expected_epoch=material["epoch"],
            payload=modified_payload,
        )


def test_share_from_wrong_epoch_cannot_be_reconstructed():
    material = create_test_material()
    verified_shares = decrypt_test_shares(material)

    modified_share = replace(
        verified_shares[0],
        epoch=material["epoch"] + 1,
    )

    with pytest.raises(ValueError, match="outdated or unexpected epoch"):
        reconstruct_verified_secret(
            [modified_share, *verified_shares[1:]],
            threshold=3,
            expected_policy_id=material["policy_id"],
            expected_epoch=material["epoch"],
        )
