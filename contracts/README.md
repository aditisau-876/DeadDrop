# DeadDrop smart contracts

## Current contents

- `src/DeadDrop.sol`: on-chain policy registry, trustee wallet registry, commitment metadata, recovery requests, EIP-712 trustee approvals, cancellation, and timelocked execution.
- `script/DeployDeadDrop.s.sol`: Foundry deployment script.
- `test/DeadDrop.t.sol`: dependency-free Foundry tests for registration, owner authorization, trustee approval, and timelock behavior.
- `foundry.toml`: Solidity compiler and Foundry project configuration.

## Requirements

Install Foundry from https://getfoundry.sh/ and verify it with:

```powershell
forge --version
```

From the `contracts` directory:

```powershell
forge build
forge test -vvv
```

## Local deployment

Start a local Anvil node in another terminal:

```powershell
anvil
```

Set the first Anvil account's private key in the current PowerShell session. Use a throwaway local development key only:

```powershell
$env:DEPLOYER_PRIVATE_KEY = "YOUR_ANVIL_ACCOUNT_PRIVATE_KEY"
forge script script/DeployDeadDrop.s.sol:DeployDeadDrop --rpc-url http://127.0.0.1:8545 --broadcast
```

Copy the deployed contract address into `backend/.env` as `BLOCKCHAIN_VERIFYING_CONTRACT_ADDRESS` and set the matching chain ID/RPC URL. Never commit private keys or `.env` files.

## Important scope limitation

The current Solidity contract enforces a **flat trustee quorum**. The backend supports composable AND/OR/THRESHOLD policy trees. These are not yet semantically equivalent. Do not represent the contract as enforcing the backend's full policy tree until a policy-tree compiler/commitment format and matching Solidity evaluator are implemented and tested.

The contract stores hashes and authorization metadata only. It does not store plaintext secrets, encrypted share payloads, or perform client-side share reconstruction. Updating commitments and incrementing an epoch is not itself proactive secret-share refresh.

Before any real-value deployment, add deployment/network configuration, monitoring, emergency pause/recovery procedures, and obtain an independent Solidity and cryptographic audit. The deployment script and tests are development scaffolding, not an audit or production approval.
