
from __future__ import annotations

import os
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session
from web3 import Web3

from app.core.config import settings
from app.models.asset import ProtectedAsset
from app.models.policy import Policy


ROTATION_RECONCILIATION_ABI = [
    {
        "type": "function",
        "name": "policies",
        "stateMutability": "view",
        "inputs": [{"name": "", "type": "bytes32"}],
        "outputs": [
            {"name": "policyHash", "type": "bytes32"},
            {"name": "version", "type": "uint64"},
            {"name": "epoch", "type": "uint64"},
            {"name": "timelockDuration", "type": "uint64"},
            {"name": "quorum", "type": "uint16"},
            {"name": "active", "type": "bool"},
        ],
    },
    {
        "type": "function",
        "name": "assets",
        "stateMutability": "view",
        "inputs": [{"name": "", "type": "bytes32"}],
        "outputs": [
            {"name": "policyKey", "type": "bytes32"},
            {"name": "assetHash", "type": "bytes32"},
            {"name": "epoch", "type": "uint64"},
            {"name": "exists", "type": "bool"},
        ],
    },
]


def _id_hash(value: str) -> bytes:
    """Match the contract's keccak256(bytes(id)) identifier."""
    return Web3.keccak(text=value)


def _epoch_mismatch(
    *,
    entity_type: str,
    entity_id: str,
    database_epoch: int,
    onchain_epoch: int,
) -> dict[str, Any] | None:
    """Return a mismatch record when two epochs differ."""
    if int(database_epoch) == int(onchain_epoch):
        return None

    return {
        "type": f"{entity_type.upper()}_EPOCH_MISMATCH",
        "entity_id": entity_id,
        "database_epoch": int(database_epoch),
        "onchain_epoch": int(onchain_epoch),
    }


def reconcile_rotation_state(db: Session) -> dict[str, Any]:
    """
    Compare policy and protected-asset epochs with confirmed contract state.

    This function is read-only. It never updates the database or blockchain.
    """

    contract_address = settings.blockchain_verifying_contract_address

    if not Web3.is_address(contract_address):
        raise ValueError("Invalid blockchain contract address.")

    web3 = Web3(
        Web3.HTTPProvider(
            settings.blockchain_rpc_url,
            request_kwargs={"timeout": 30},
        )
    )

    if not web3.is_connected():
        raise ConnectionError("Blockchain RPC is unavailable.")

    actual_chain_id = int(web3.eth.chain_id)
    expected_chain_id = int(settings.blockchain_chain_id)

    if actual_chain_id != expected_chain_id:
        raise ValueError(
            f"Network mismatch: expected chain {expected_chain_id}, "
            f"received {actual_chain_id}."
        )

    checksum_address = Web3.to_checksum_address(contract_address)

    latest_block = int(web3.eth.block_number)
    confirmations = max(
        0,
        int(os.getenv("BLOCKCHAIN_INDEXER_CONFIRMATIONS", "3")),
    )
    confirmed_block = latest_block - confirmations

    if confirmed_block < 0:
        return {
            "status": "waiting_for_confirmations",
            "chain_id": actual_chain_id,
            "latest_block": latest_block,
            "confirmed_block": confirmed_block,
            "confirmations_required": confirmations,
            "checked_policies": 0,
            "checked_assets": 0,
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
        abi=ROTATION_RECONCILIATION_ABI,
    )

    policies = db.scalars(
        select(Policy).order_by(Policy.id)
    ).all()

    assets = db.scalars(
        select(ProtectedAsset).order_by(ProtectedAsset.id)
    ).all()

    assets_by_policy: dict[str, list[ProtectedAsset]] = {}

    for asset in assets:
        assets_by_policy.setdefault(asset.policy_id, []).append(asset)

    mismatches: list[dict[str, Any]] = []
    checked_policies = 0
    checked_assets = 0

    for policy in policies:
        checked_policies += 1

        try:
            policy_key = _id_hash(policy.id)

            chain_policy = contract.functions.policies(
                policy_key
            ).call(block_identifier=confirmed_block)

            (
                policy_hash,
                chain_version,
                chain_epoch,
                _timelock_duration,
                _quorum,
                chain_active,
            ) = chain_policy

            if bytes(policy_hash) == b"\x00" * 32:
                mismatches.append({
                    "type": "POLICY_MISSING_ONCHAIN",
                    "entity_id": policy.id,
                    "database_epoch": int(policy.epoch),
                })
                continue

            epoch_issue = _epoch_mismatch(
                entity_type="policy",
                entity_id=policy.id,
                database_epoch=policy.epoch,
                onchain_epoch=chain_epoch,
            )

            if epoch_issue:
                mismatches.append(epoch_issue)

            if int(policy.version) != int(chain_version):
                mismatches.append({
                    "type": "POLICY_VERSION_MISMATCH",
                    "entity_id": policy.id,
                    "database_version": int(policy.version),
                    "onchain_version": int(chain_version),
                })

            if bool(policy.active) != bool(chain_active):
                mismatches.append({
                    "type": "POLICY_ACTIVE_STATUS_MISMATCH",
                    "entity_id": policy.id,
                    "database_active": bool(policy.active),
                    "onchain_active": bool(chain_active),
                })

            for asset in assets_by_policy.get(policy.id, []):
                checked_assets += 1

                asset_key = _id_hash(asset.id)

                chain_asset = contract.functions.assets(
                    asset_key
                ).call(block_identifier=confirmed_block)

                (
                    chain_asset_policy_key,
                    _asset_hash,
                    chain_asset_epoch,
                    asset_exists,
                ) = chain_asset

                if not asset_exists:
                    mismatches.append({
                        "type": "ASSET_MISSING_ONCHAIN",
                        "entity_id": asset.id,
                        "policy_id": policy.id,
                        "database_epoch": int(asset.epoch),
                    })
                    continue

                if bytes(chain_asset_policy_key) != bytes(policy_key):
                    mismatches.append({
                        "type": "ASSET_POLICY_KEY_MISMATCH",
                        "entity_id": asset.id,
                        "policy_id": policy.id,
                    })

                asset_epoch_issue = _epoch_mismatch(
                    entity_type="asset",
                    entity_id=asset.id,
                    database_epoch=asset.epoch,
                    onchain_epoch=chain_asset_epoch,
                )

                if asset_epoch_issue:
                    asset_epoch_issue["policy_id"] = policy.id
                    mismatches.append(asset_epoch_issue)

        except Exception as exc:
            mismatches.append({
                "type": "ROTATION_RECONCILIATION_READ_ERROR",
                "entity_id": policy.id,
                "message": str(exc),
            })

    return {
        "status": "consistent" if not mismatches else "mismatches_found",
        "chain_id": actual_chain_id,
        "contract_address": checksum_address,
        "latest_block": latest_block,
        "confirmed_block": confirmed_block,
        "confirmations_required": confirmations,
        "checked_policies": checked_policies,
        "checked_assets": checked_assets,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }
