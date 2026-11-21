
from __future__ import annotations

from eth_account import Account
from eth_account.messages import encode_typed_data

from app.core.config import settings


def _domain() -> dict:
    return {
        "name": "DeadDrop",
        "version": "1",
        "chainId": settings.blockchain_chain_id,
        "verifyingContract": (
            settings.blockchain_verifying_contract_address
        ),
    }


def build_approval_typed_data(
    *,
    recovery_id: str,
    policy_id: str,
    trustee_id: str,
    incident_hash: str,
    policy_version: int,
    policy_epoch: int,
) -> dict:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "RecoveryApproval": [
                {"name": "recoveryId", "type": "string"},
                {"name": "policyId", "type": "string"},
                {"name": "trusteeId", "type": "string"},
                {"name": "incidentHash", "type": "string"},
                {"name": "policyVersion", "type": "uint256"},
                {"name": "policyEpoch", "type": "uint256"},
            ],
        },
        "primaryType": "RecoveryApproval",
        "domain": _domain(),
        "message": {
            "recoveryId": recovery_id,
            "policyId": policy_id,
            "trusteeId": trustee_id,
            "incidentHash": incident_hash,
            "policyVersion": policy_version,
            "policyEpoch": policy_epoch,
        },
    }


def verify_approval_signature(
    *,
    signature: str,
    expected_wallet: str,
    recovery_id: str,
    policy_id: str,
    trustee_id: str,
    incident_hash: str,
    policy_version: int,
    policy_epoch: int,
) -> bool:
    if not expected_wallet:
        return False

    try:
        typed_data = build_approval_typed_data(
            recovery_id=recovery_id,
            policy_id=policy_id,
            trustee_id=trustee_id,
            incident_hash=incident_hash,
            policy_version=policy_version,
            policy_epoch=policy_epoch,
        )

        signable_message = encode_typed_data(
            full_message=typed_data
        )

        recovered_address = Account.recover_message(
            signable_message,
            signature=signature,
        )

        return (
            recovered_address.lower()
            == expected_wallet.lower()
        )

    except (ValueError, TypeError, KeyError):
        return False



def build_share_release_typed_data(
    *,
    challenge_id: str,
    nonce: str,
    recovery_id: str,
    asset_id: str,
    policy_id: str,
    trustee_id: str,
    policy_version: int,
    epoch: int,
) -> dict:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "ShareRelease": [
                {"name": "challengeId", "type": "string"},
                {"name": "nonce", "type": "string"},
                {"name": "recoveryId", "type": "string"},
                {"name": "assetId", "type": "string"},
                {"name": "policyId", "type": "string"},
                {"name": "trusteeId", "type": "string"},
                {"name": "policyVersion", "type": "uint256"},
                {"name": "epoch", "type": "uint256"},
            ],
        },
        "primaryType": "ShareRelease",
        "domain": _domain(),
        "message": {
            "challengeId": challenge_id,
            "nonce": nonce,
            "recoveryId": recovery_id,
            "assetId": asset_id,
            "policyId": policy_id,
            "trusteeId": trustee_id,
            "policyVersion": policy_version,
            "epoch": epoch,
        },
    }


def verify_share_release_signature(
    *,
    signature: str,
    expected_wallet: str,
    challenge_id: str,
    nonce: str,
    recovery_id: str,
    asset_id: str,
    policy_id: str,
    trustee_id: str,
    policy_version: int,
    epoch: int,
) -> bool:
    if not expected_wallet:
        return False

    try:
        typed_data = build_share_release_typed_data(
            challenge_id=challenge_id,
            nonce=nonce,
            recovery_id=recovery_id,
            asset_id=asset_id,
            policy_id=policy_id,
            trustee_id=trustee_id,
            policy_version=policy_version,
            epoch=epoch,
        )

        signable_message = encode_typed_data(
            full_message=typed_data
        )

        recovered_address = Account.recover_message(
            signable_message,
            signature=signature,
        )

        return (
            recovered_address.lower()
            == expected_wallet.lower()
        )

    except (ValueError, TypeError, KeyError):
        return False

