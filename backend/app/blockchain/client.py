
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from web3 import Web3
from web3.exceptions import TransactionNotFound


DEADDROP_ABI = [
    {
        "type": "function",
        "name": "owner",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
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
        "name": "recoveries",
        "stateMutability": "view",
        "inputs": [{"name": "", "type": "bytes32"}],
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
        "name": "recoveryArtifactHashes",
        "stateMutability": "view",
        "inputs": [{"name": "", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bytes32"}],
    },
    {
        "type": "function",
        "name": "trusteeCount",
        "stateMutability": "view",
        "inputs": [{"name": "", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "trustees",
        "stateMutability": "view",
        "inputs": [
            {"name": "", "type": "bytes32"},
            {"name": "", "type": "address"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "approved",
        "stateMutability": "view",
        "inputs": [
            {"name": "", "type": "bytes32"},
            {"name": "", "type": "address"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
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
    {
        "type": "function",
        "name": "policyAssetCount",
        "stateMutability": "view",
        "inputs": [{"name": "", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "rotatePolicyAssetCommitments",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "policyId", "type": "string"},
            {"name": "expectedEpoch", "type": "uint64"},
            {"name": "newEpoch", "type": "uint64"},
            {"name": "assetIds", "type": "string[]"},
            {"name": "trusteeWallets", "type": "address[]"},
            {"name": "newCommitments", "type": "bytes32[][]"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "getAssetCommitment",
        "stateMutability": "view",
        "inputs": [
            {"name": "assetId", "type": "string"},
            {"name": "trusteeWallet", "type": "address"},
        ],
        "outputs": [{"name": "", "type": "bytes32"}],
    },
    {
        "type": "function",
        "name": "getCommitments",
        "stateMutability": "view",
        "inputs": [{"name": "policyId", "type": "string"}],
        "outputs": [{"name": "", "type": "bytes32[]"}],
    },
]


RECOVERY_STATES = {
    0: "NONE",
    1: "REQUESTED",
    2: "EXECUTED",
    3: "CANCELLED",
}


@dataclass
class BlockchainClient:
    rpc_url: str
    chain_id: int
    contract_address: str | None = None

    
    def __post_init__(self) -> None:
        self.web3 = Web3(
            Web3.HTTPProvider(
                self.rpc_url,
                request_kwargs={"timeout": 15},
            )
        )

        self.contract = None

        if (
            self.contract_address
            and Web3.is_address(self.contract_address)
        ):
            self.contract_address = Web3.to_checksum_address(
                self.contract_address
            )

            self.contract = self.web3.eth.contract(
                address=self.contract_address,
                abi=DEADDROP_ABI,
            )
        else:
            self.contract_address = None

    @property
    def configured(self) -> bool:
        return self.contract is not None

    @property
    def contract_address_input(self) -> str:
        return self.__dict__.get("_configured_contract_address", "") or ""

    @property
    def contract_address_configured(self) -> bool:
        return bool(
            self.__dict__.get("_configured_contract_address")
        )

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "contract_address":
            object.__setattr__(
                self,
                "_configured_contract_address",
                value,
            )
        object.__setattr__(self, name, value)

    @property
    def connected(self) -> bool:
        try:
            return self.web3.is_connected()
        except Exception:
            return False

    @property
    def configured(self) -> bool:
        return self.contract is not None

    def get_chain_id(self) -> int | None:
        if not self.connected:
            return None

        try:
            return self.web3.eth.chain_id
        except Exception:
            return None

    def get_block_number(self) -> int | None:
        if not self.connected:
            return None

        try:
            return self.web3.eth.block_number
        except Exception:
            return None

    def get_contract_code_size(self) -> int | None:
        if not self.connected or not self.contract_address:
            return None

        try:
            code = self.web3.eth.get_code(
                self.contract_address
            )
            return len(code)
        except Exception:
            return None

    def get_status(self) -> dict:
        network_chain_id = self.get_chain_id()
        code_size = self.get_contract_code_size()

        chain_matches = (
            network_chain_id == self.chain_id
            if network_chain_id is not None
            else False
        )

        contract_deployed = (
            code_size is not None and code_size > 0
        )

        return {
            "rpc_connected": self.connected,
            "configured_chain_id": self.chain_id,
            "network_chain_id": network_chain_id,
            "chain_matches": chain_matches,
            "contract_configured": self.configured,
            "contract_address": self.contract_address,
            "contract_deployed": contract_deployed,
            "contract_code_size": code_size,
            "block_number": self.get_block_number(),
            "ready": (
                self.connected
                and chain_matches
                and self.configured
                and contract_deployed
            ),
        }

    def _require_contract(self):
        if not self.connected:
            raise RuntimeError("Blockchain RPC is unavailable.")

        network_chain_id = self.get_chain_id()

        if network_chain_id != self.chain_id:
            raise RuntimeError(
                "Connected network chain ID does not match "
                "BLOCKCHAIN_CHAIN_ID."
            )

        if self.contract is None:
            raise RuntimeError(
                "DeadDrop contract address is not configured."
            )

        code_size = self.get_contract_code_size()

        if not code_size:
            raise RuntimeError(
                "No contract bytecode exists at the configured address."
            )

        return self.contract

    @staticmethod
    def _id_hash(value: str) -> bytes:
        if not value or not value.strip():
            raise ValueError("Identifier cannot be empty.")

        return Web3.keccak(text=value)

    def get_policy(self, policy_id: str) -> dict:
        contract = self._require_contract()
        key = self._id_hash(policy_id)

        (
            policy_hash,
            version,
            epoch,
            timelock_duration,
            quorum,
            active,
        ) = contract.functions.policies(key).call()

        exists = bytes(policy_hash) != bytes(32)

        if not exists:
            return {
                "exists": False,
                "policy_id": policy_id,
            }

        trustee_count = contract.functions.trusteeCount(
            key
        ).call()

        commitments = contract.functions.getCommitments(
            policy_id
        ).call()

        return {
            "exists": True,
            "policy_id": policy_id,
            "policy_key": Web3.to_hex(key),
            "policy_hash": Web3.to_hex(policy_hash),
            "version": version,
            "epoch": epoch,
            "timelock_duration": timelock_duration,
            "quorum": quorum,
            "active": active,
            "trustee_count": trustee_count,
            "commitments": [
                Web3.to_hex(item)
                for item in commitments
            ],
        }

    def get_asset(self, asset_id: str) -> dict:
        contract = self._require_contract()
        key = self._id_hash(asset_id)
        policy_key, asset_hash, epoch, exists = contract.functions.assets(key).call()
        return {
            "exists": bool(exists),
            "asset_id": asset_id,
            "asset_key": Web3.to_hex(key),
            "policy_key": Web3.to_hex(policy_key),
            "asset_hash": Web3.to_hex(asset_hash),
            "epoch": int(epoch),
        }

    def get_asset_commitment(self, asset_id: str, wallet_address: str) -> str:
        contract = self._require_contract()
        if not Web3.is_address(wallet_address):
            raise ValueError("Invalid trustee wallet address.")
        value = contract.functions.getAssetCommitment(
            asset_id,
            Web3.to_checksum_address(wallet_address),
        ).call()
        return Web3.to_hex(value)

    def is_trustee(
        self,
        policy_id: str,
        wallet_address: str,
    ) -> bool:
        contract = self._require_contract()

        if not Web3.is_address(wallet_address):
            raise ValueError("Invalid trustee wallet address.")

        key = self._id_hash(policy_id)
        wallet = Web3.to_checksum_address(wallet_address)

        return bool(
            contract.functions.trustees(
                key,
                wallet,
            ).call()
        )

    def has_approved(
        self,
        recovery_id: str,
        wallet_address: str,
    ) -> bool:
        contract = self._require_contract()

        if not Web3.is_address(wallet_address):
            raise ValueError("Invalid wallet address.")

        recovery_key = self._id_hash(recovery_id)
        wallet = Web3.to_checksum_address(wallet_address)

        return bool(
            contract.functions.approved(
                recovery_key,
                wallet,
            ).call()
        )

    def get_recovery(self, recovery_id: str) -> dict:
        contract = self._require_contract()
        key = self._id_hash(recovery_id)

        (
            policy_key,
            incident_hash,
            requester,
            policy_version,
            policy_epoch,
            requested_at,
            execute_after,
            expires_at,
            approvals,
            state,
        ) = contract.functions.recoveries(key).call()

        state_name = RECOVERY_STATES.get(
            state,
            "UNKNOWN",
        )

        exists = state != 0

        return {
            "exists": exists,
            "recovery_id": recovery_id,
            "recovery_key": Web3.to_hex(key),
            "policy_key": Web3.to_hex(policy_key),
            "incident_hash": Web3.to_hex(incident_hash),
            "requester": requester,
            "policy_version": policy_version,
            "policy_epoch": policy_epoch,
            "requested_at": requested_at,
            "execute_after": execute_after,
            "expires_at": expires_at,
            "approvals": approvals,
            "state": state_name,
            "state_code": state,
        }

    
    def verify_transaction(
        self,
        transaction_hash: str,
    ) -> dict:
        if not self.connected:
            raise RuntimeError("Blockchain RPC is unavailable.")

        import re

        if not isinstance(transaction_hash, str) or not re.fullmatch(
            r"(0x)?[0-9a-fA-F]{64}",
            transaction_hash,
        ):
            raise ValueError("Invalid 32-byte transaction hash.")

        tx_hash = (
            transaction_hash
            if transaction_hash.startswith("0x")
            else "0x" + transaction_hash
        )

        try:
            transaction = self.web3.eth.get_transaction(
                tx_hash
            )
        except TransactionNotFound:
            return {
                "found": False,
                "transaction_hash": tx_hash,
            }

        try:
            receipt = self.web3.eth.get_transaction_receipt(
                tx_hash
            )
        except TransactionNotFound:
            return {
                "found": True,
                "mined": False,
                "transaction_hash": tx_hash,
                "from": transaction.get("from"),
                "to": transaction.get("to"),
                "successful": None,
                "confirmations": 0,
            }

        target = transaction.get("to")

        target_is_contract = (
            target is not None
            and self.contract_address is not None
            and Web3.to_checksum_address(target)
            == self.contract_address
        )

        current_block = self.web3.eth.block_number
        block_number = receipt.get("blockNumber")

        confirmations = (
            max(0, current_block - block_number + 1)
            if block_number is not None
            else 0
        )

        transaction_status = int(receipt.get("status", 0))

        return {
            "found": True,
            "mined": True,
            "transaction_hash": tx_hash,
            "from": transaction.get("from"),
            "to": target,
            "to_deadrop_contract": target_is_contract,
            "block_number": block_number,
            "confirmations": confirmations,
            "status": transaction_status,
            "successful": transaction_status == 1,
            "gas_used": receipt.get("gasUsed"),
            "transaction_index": receipt.get("transactionIndex"),
            "log_count": len(receipt.get("logs", [])),
        }
