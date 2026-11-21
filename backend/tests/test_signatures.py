
from eth_account import Account
from eth_account.messages import encode_typed_data

from app.crypto.signatures import (
    build_approval_typed_data,
    build_share_release_typed_data,
    verify_approval_signature,
    verify_share_release_signature,
)


def test_valid_trustee_signature_is_accepted():
    account = Account.create()

    values = {
        "recovery_id": "recovery-123",
        "policy_id": "policy-123",
        "trustee_id": "trustee-123",
        "incident_hash": "incident-hash-123",
        "policy_version": 1,
        "policy_epoch": 1,
    }

    typed_data = build_approval_typed_data(**values)
    message = encode_typed_data(full_message=typed_data)

    signed = Account.sign_message(
        message,
        private_key=account.key,
    )

    assert verify_approval_signature(
        signature=signed.signature.hex(),
        expected_wallet=account.address,
        **values,
    )


def test_signature_from_wrong_wallet_is_rejected():
    signer = Account.create()
    expected_wallet = Account.create().address

    values = {
        "recovery_id": "recovery-123",
        "policy_id": "policy-123",
        "trustee_id": "trustee-123",
        "incident_hash": "incident-hash-123",
        "policy_version": 1,
        "policy_epoch": 1,
    }

    typed_data = build_approval_typed_data(**values)
    message = encode_typed_data(full_message=typed_data)

    signed = Account.sign_message(
        message,
        private_key=signer.key,
    )

    assert not verify_approval_signature(
        signature=signed.signature.hex(),
        expected_wallet=expected_wallet,
        **values,
    )


def test_signature_cannot_be_reused_for_another_recovery():
    account = Account.create()

    values = {
        "recovery_id": "recovery-original",
        "policy_id": "policy-123",
        "trustee_id": "trustee-123",
        "incident_hash": "incident-hash-123",
        "policy_version": 1,
        "policy_epoch": 1,
    }

    typed_data = build_approval_typed_data(**values)
    message = encode_typed_data(full_message=typed_data)

    signed = Account.sign_message(
        message,
        private_key=account.key,
    )

    changed_values = {
        **values,
        "recovery_id": "recovery-different",
    }

    assert not verify_approval_signature(
        signature=signed.signature.hex(),
        expected_wallet=account.address,
        **changed_values,
    )


def test_invalid_signature_is_rejected():
    assert not verify_approval_signature(
        signature="not-a-valid-signature",
        expected_wallet="0x0000000000000000000000000000000000000001",
        recovery_id="recovery-123",
        policy_id="policy-123",
        trustee_id="trustee-123",
        incident_hash="incident-hash-123",
        policy_version=1,
        policy_epoch=1,
    )


def test_share_release_signature_is_bound_to_one_challenge_and_policy_version():
    account = Account.create()
    values = {
        "challenge_id": "challenge-123",
        "nonce": "random-one-time-nonce",
        "recovery_id": "recovery-123",
        "asset_id": "asset-123",
        "policy_id": "policy-123",
        "trustee_id": "trustee-123",
        "policy_version": 4,
        "epoch": 2,
    }
    typed_data = build_share_release_typed_data(**values)
    signable = encode_typed_data(full_message=typed_data)
    signed = Account.sign_message(signable, private_key=account.key)

    assert verify_share_release_signature(
        signature=signed.signature.hex(),
        expected_wallet=account.address,
        **values,
    )
    assert not verify_share_release_signature(
        signature=signed.signature.hex(),
        expected_wallet=account.address,
        **{**values, "policy_version": 5},
    )
