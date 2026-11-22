
from __future__ import annotations

import calendar
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session
from web3 import Web3

from app.core.config import settings
from app.models.blockchain_projection import (
    BlockchainRecoveryProjection,
)
from app.models.recovery import RecoveryRequest


RECONCILIATION_ABI = [
    {
        "type": "function",
        "name": "recoveries",
        "stateMutability": "view",
        "inputs": [
            {"name": "", "type": "bytes32"},
        ],
        "outputs": [
            {"name": "policyKey", "type": "bytes32"},
            {"name": "incidentHash", "type": "bytes32"},
            {"name": "requester", "type": "address"},
            {"name": "policyVersion", "type": "uint64"},
            {"name": "policyEpoch", "type": "uint64"},
            {"name": "requestedAt", "type": "uint64"},
            {"name": "executeAfter", "type": "uint64"},
            {"name": "expiresAt", "type": "uint64"},
            {"name": "approvals", "type": "uint16"},
            {"name": "state", "type": "uint8"},
        ],
    },
    {
        "type": "function",
        "name": "policies",
        "stateMutability": "view",
        "inputs": [
            {"name": "", "type": "bytes32"},
        ],
        "outputs": [
            {"name": "policyHash", "type": "bytes32"},
            {"name": "version", "type": "uint64"},
            {"name": "epoch", "type": "uint64"},
            {"name": "timelockDuration", "type": "uint64"},
            {"name": "quorum", "type": "uint16"},
            {"name": "active", "type": "bool"},
        ],
    },
]


ONCHAIN_STATES = {
    0: "UNKNOWN",
    1: "REQUESTED",
    2: "EXECUTED",
    3: "CANCELLED",
}


def _normalize_hash(value: Any) -> str:
    """Normalize bytes, HexBytes, or hexadecimal strings."""

    if isinstance(value, bytes):
        return "0x" + value.hex().lower()

    if hasattr(value, "hex") and not isinstance(value, str):
        result = value.hex()

        if not result.startswith("0x"):
            result = "0x" + result

        return result.lower()

    result = str(value).lower()

    if not result.startswith("0x"):
        result = "0x" + result

    return result


def _as_bytes32(value: str) -> bytes:
    """Convert a 32-byte hexadecimal string to bytes."""

    if not isinstance(value, str):
        raise ValueError("Expected a hexadecimal string.")

    normalized = value.removeprefix("0x")

    if len(normalized) != 64:
        raise ValueError(
            "Expected a 32-byte hexadecimal value."
        )

    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(
            "Invalid hexadecimal recovery key."
        ) from exc


def _utc_epoch(value: Any) -> int:
    """
    Convert a database datetime to a Unix timestamp.

    Database datetime values in this project are stored as UTC,
    including timezone-naive datetime values.
    """

    if value is None:
        return 0

    return calendar.timegm(value.utctimetuple())


def _add_mismatch(
    mismatches: list[dict[str, Any]],
    mismatch_type: str,
    recovery_key: str,
    field: str | None = None,
    indexed_value: Any = None,
    onchain_value: Any = None,
    message: str | None = None,
) -> None:
    item: dict[str, Any] = {
        "type": mismatch_type,
        "recovery_key": recovery_key,
    }

    if field is not None:
        item["field"] = field

    if indexed_value is not None:
        item["indexed_value"] = indexed_value

    if onchain_value is not None:
        item["onchain_value"] = onchain_value

    if message is not None:
        item["message"] = message

    mismatches.append(item)


def reconcile_blockchain_state(
    db: Session,
) -> dict[str, Any]:
    """
    Compare indexed recovery projections with confirmed contract state.

    This operation is read-only. It does not modify:
    - RecoveryRequest
    - BlockchainRecoveryProjection
    - Policy
    - RecoveryApproval

    The contract reads are pinned to a confirmed block so the comparison
    does not mix state from different moving blockchain heads.
    """

    address = (
        settings.blockchain_verifying_contract_address
    )

    if not Web3.is_address(address):
        raise ValueError(
            "Invalid blockchain contract address."
        )

    web3 = Web3(
        Web3.HTTPProvider(
            settings.blockchain_rpc_url,
            request_kwargs={"timeout": 30},
        )
    )

    if not web3.is_connected():
        raise ConnectionError(
            "Blockchain RPC is unavailable."
        )

    actual_chain_id = int(web3.eth.chain_id)
    expected_chain_id = int(
        settings.blockchain_chain_id
    )

    if actual_chain_id != expected_chain_id:
        raise ValueError(
            f"Network mismatch: expected chain "
            f"{expected_chain_id}, received {actual_chain_id}."
        )

    checksum_address = Web3.to_checksum_address(
        address
    )

    latest_block = int(web3.eth.block_number)

    confirmations = max(
        0,
        int(
            __import__("os").getenv(
                "BLOCKCHAIN_INDEXER_CONFIRMATIONS",
                "3",
            )
        ),
    )

    confirmed_block = latest_block - confirmations

    if confirmed_block < 0:
        return {
            "status": "waiting_for_confirmations",
            "chain_id": actual_chain_id,
            "latest_block": latest_block,
            "confirmed_block": confirmed_block,
            "checked_recoveries": 0,
            "mismatch_count": 0,
            "mismatches": [],
        }

    bytecode = web3.eth.get_code(
        checksum_address,
        block_identifier=confirmed_block,
    )

    if not bytecode:
        raise ValueError(
            "No contract bytecode exists at the configured address."
        )

    contract = web3.eth.contract(
        address=checksum_address,
        abi=RECONCILIATION_ABI,
    )

    projections = db.scalars(
        select(BlockchainRecoveryProjection).where(
            BlockchainRecoveryProjection.chain_id
            == actual_chain_id,
            BlockchainRecoveryProjection.contract_address
            == checksum_address,
        )
    ).all()

    mismatches: list[dict[str, Any]] = []
    checked = 0

    for projection in projections:
        checked += 1

        recovery_key = projection.recovery_key

        try:
            recovery_key_bytes = _as_bytes32(
                recovery_key
            )

            chain_recovery = (
                contract.functions.recoveries(
                    recovery_key_bytes
                ).call(
                    block_identifier=confirmed_block
                )
            )

            (
                chain_policy_key,
                incident_hash,
                requester,
                recovery_policy_version,
                recovery_policy_epoch,
                requested_at,
                execute_after,
                expires_at,
                approvals,
                state_number,
            ) = chain_recovery

            chain_state = ONCHAIN_STATES.get(
                int(state_number),
                "UNRECOGNIZED",
            )

            chain_policy_key_hex = _normalize_hash(
                chain_policy_key
            )

            # Compare indexed recovery information with the contract.
            comparisons = {
                "state": (
                    str(projection.state).upper(),
                    chain_state,
                ),
                "policy_key": (
                    (
                        projection.policy_key.lower()
                        if projection.policy_key
                        else None
                    ),
                    chain_policy_key_hex,
                ),
                "requester": (
                    (
                        projection.requester.lower()
                        if projection.requester
                        else None
                    ),
                    requester.lower(),
                ),
                "approvals": (
                    int(projection.approvals),
                    int(approvals),
                ),
                "execute_after": (
                    _utc_epoch(
                        projection.execute_after
                    ),
                    int(execute_after),
                ),
                "expires_at": (
                    _utc_epoch(
                        projection.expires_at
                    ),
                    int(expires_at),
                ),
                "requested_at": (
                    _utc_epoch(
                        projection.requested_at
                    ),
                    int(requested_at),
                ),
            }

            for field, values in comparisons.items():
                indexed_value, onchain_value = values

                if indexed_value != onchain_value:
                    _add_mismatch(
                        mismatches=mismatches,
                        mismatch_type="PROJECTION_MISMATCH",
                        recovery_key=recovery_key,
                        field=field,
                        indexed_value=indexed_value,
                        onchain_value=onchain_value,
                    )

            # Compare the corresponding off-chain recovery.
            recovery = None

            if projection.recovery_id:
                recovery = db.get(
                    RecoveryRequest,
                    projection.recovery_id,
                )

            if recovery is not None:
                if int(recovery.policy_version) != int(
                    recovery_policy_version
                ):
                    _add_mismatch(
                        mismatches=mismatches,
                        mismatch_type=(
                            "OFFCHAIN_POLICY_VERSION_MISMATCH"
                        ),
                        recovery_key=recovery_key,
                        field="policy_version",
                        indexed_value=int(
                            recovery.policy_version
                        ),
                        onchain_value=int(
                            recovery_policy_version
                        ),
                    )

                if int(recovery.policy_epoch) != int(
                    recovery_policy_epoch
                ):
                    _add_mismatch(
                        mismatches=mismatches,
                        mismatch_type=(
                            "OFFCHAIN_POLICY_EPOCH_MISMATCH"
                        ),
                        recovery_key=recovery_key,
                        field="policy_epoch",
                        indexed_value=int(
                            recovery.policy_epoch
                        ),
                        onchain_value=int(
                            recovery_policy_epoch
                        ),
                    )

                # Terminal states should agree between the
                # off-chain record and confirmed chain state.
                if chain_state in {
                    "EXECUTED",
                    "CANCELLED",
                }:
                    offchain_state = str(
                        recovery.status
                    ).upper()

                    if offchain_state != chain_state:
                        _add_mismatch(
                            mismatches=mismatches,
                            mismatch_type=(
                                "OFFCHAIN_TERMINAL_STATE_MISMATCH"
                            ),
                            recovery_key=recovery_key,
                            field="status",
                            indexed_value=offchain_state,
                            onchain_value=chain_state,
                        )

            # Compare the policy's current state with the policy
            # version and epoch captured when this recovery began.
            if chain_policy_key != b"\x00" * 32:
                chain_policy = (
                    contract.functions.policies(
                        chain_policy_key
                    ).call(
                        block_identifier=confirmed_block
                    )
                )

                (
                    policy_hash,
                    current_version,
                    current_epoch,
                    timelock_duration,
                    quorum,
                    active,
                ) = chain_policy

                if int(current_version) != int(
                    recovery_policy_version
                ):
                    _add_mismatch(
                        mismatches=mismatches,
                        mismatch_type=(
                            "ONCHAIN_POLICY_CHANGED_SINCE_REQUEST"
                        ),
                        recovery_key=recovery_key,
                        field="policy_version",
                        indexed_value=int(
                            recovery_policy_version
                        ),
                        onchain_value=int(current_version),
                    )

                if int(current_epoch) != int(
                    recovery_policy_epoch
                ):
                    _add_mismatch(
                        mismatches=mismatches,
                        mismatch_type=(
                            "ONCHAIN_POLICY_EPOCH_CHANGED_SINCE_REQUEST"
                        ),
                        recovery_key=recovery_key,
                        field="policy_epoch",
                        indexed_value=int(
                            recovery_policy_epoch
                        ),
                        onchain_value=int(current_epoch),
                    )

                if not active:
                    _add_mismatch(
                        mismatches=mismatches,
                        mismatch_type="ONCHAIN_POLICY_INACTIVE",
                        recovery_key=recovery_key,
                    )

        except Exception as exc:
            _add_mismatch(
                mismatches=mismatches,
                mismatch_type="CONTRACT_READ_ERROR",
                recovery_key=recovery_key,
                message=str(exc),
            )

    return {
        "status": (
            "consistent"
            if not mismatches
            else "mismatches_found"
        ),
        "chain_id": actual_chain_id,
        "contract_address": checksum_address,
        "latest_block": latest_block,
        "confirmed_block": confirmed_block,
        "confirmations_required": confirmations,
        "checked_recoveries": checked,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }
