from __future__ import annotations

from dataclasses import dataclass

from web3 import Web3


@dataclass
class BlockchainClient:
    rpc_url: str
    chain_id: int

    def __post_init__(self) -> None:
        self.web3 = Web3(
            Web3.HTTPProvider(self.rpc_url)
        )

    @property
    def connected(self) -> bool:
        return self.web3.is_connected()

    def get_chain_id(self) -> int | None:
        if not self.connected:
            return None

        return self.web3.eth.chain_id

    def get_block_number(self) -> int | None:
        if not self.connected:
            return None

        return self.web3.eth.block_number