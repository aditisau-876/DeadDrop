import { BrowserProvider, Contract } from "ethers";
import { authApiRequest } from "../authApi";

import {
  createPolicyRotationRequest,
  type RotationTrustee,
} from "./shareRotation";

interface PolicyRotationDetails {
  id: string;
  epoch: number;
  version: number;
  active: boolean;
  trustee_ids: string[];
}

interface RotationAsset {
  id: string;
  policy_id: string;
  epoch: number;
  threshold: number;
}

interface RotationTrusteeRecord {
  id: string;
  name: string;
  public_key: string | null;
  active: boolean;
}

interface PreparedOnchainRotation {
  policy_id: string;
  chain_id: number;
  contract_address: string;
  contract_owner: string;
  previous_epoch: number;
  new_epoch: number;
  asset_ids: string[];
  trustee_wallets: string[];
  new_commitments: string[][];
  function_signature: string;
  message: string;
}

export interface PolicyRotationResult {
  policy_id: string;
  previous_epoch: number;
  new_epoch: number;
  new_policy_version: number;
  updated_asset_count: number;
  inserted_share_count: number;
  message: string;
  verified: boolean;
  transaction?: {
    hash?: string;
    [key: string]: unknown;
  };
}

export interface RotatePolicyInput {
  policyId: string;
  /**
   * Original AES-256 keys reconstructed and authenticated in this tab.
   * These keys are used locally to create new Shamir shares and are
   * never included in an API request.
   */
  recoveredAssetKeys: Map<string, Uint8Array>;
}

const rotationContractAbi = [
  "function rotatePolicyAssetCommitments(string policyId,uint64 expectedEpoch,uint64 newEpoch,string[] assetIds,address[] trusteeWallets,bytes32[][] newCommitments)",
];

/**
 * Complete on-chain share rotation:
 * 1. Generate new Shamir shares and encrypted envelopes locally.
 * 2. Ask the backend to validate the complete rotation and prepare calldata.
 * 3. Have the configured contract-owner wallet submit the Solidity call.
 * 4. Wait for mining.
 * 5. Ask the backend to verify the exact transaction and chain state.
 * 6. The backend persists the database projection only after verification.
 */
export async function rotatePolicyShares(
  input: RotatePolicyInput,
): Promise<PolicyRotationResult> {
  if (!input.policyId.trim()) {
    throw new Error("Policy ID is required.");
  }

  if (input.recoveredAssetKeys.size === 0) {
    throw new Error(
      "No recovered asset keys are available in this browser tab. Recover every asset under this policy first.",
    );
  }

  if (!window.ethereum) {
    throw new Error("MetaMask was not detected. Connect the contract-owner wallet.");
  }

  const policy = await authApiRequest<PolicyRotationDetails>(
    `/api/policies/${encodeURIComponent(input.policyId)}`,
  );

  if (!policy.active) {
    throw new Error("Inactive policies cannot rotate shares.");
  }

  if (!Number.isInteger(policy.epoch) || policy.epoch < 1) {
    throw new Error("The policy has an invalid epoch.");
  }

  if (
    !Array.isArray(policy.trustee_ids) ||
    policy.trustee_ids.length < 2 ||
    new Set(policy.trustee_ids).size !== policy.trustee_ids.length
  ) {
    throw new Error("The policy must have at least two unique assigned trustees.");
  }

  const [allAssets, allTrustees] = await Promise.all([
    authApiRequest<RotationAsset[]>("/api/assets"),
    authApiRequest<RotationTrusteeRecord[]>("/api/trustees"),
  ]);

  const assets = allAssets
    .filter((asset) => asset.policy_id === policy.id)
    .sort((a, b) => a.id.localeCompare(b.id));

  if (assets.length === 0) {
    throw new Error("This policy has no protected assets to rotate.");
  }

  for (const asset of assets) {
    if (asset.epoch !== policy.epoch) {
      throw new Error(
        `Asset ${asset.id} is at epoch ${asset.epoch}, but the policy is at epoch ${policy.epoch}. Resolve the epoch mismatch before rotation.`,
      );
    }

    if (
      !Number.isInteger(asset.threshold) ||
      asset.threshold < 2 ||
      asset.threshold > policy.trustee_ids.length
    ) {
      throw new Error(`Asset ${asset.id} has an invalid recovery threshold.`);
    }
  }

  const assetIds = new Set(assets.map((asset) => asset.id));

  for (const assetId of assetIds) {
    const key = input.recoveredAssetKeys.get(assetId);
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error(
        `A recovered 32-byte AES key is missing for asset ${assetId}. Recover every protected asset under this policy before rotating.`,
      );
    }
  }

  for (const suppliedId of input.recoveredAssetKeys.keys()) {
    if (!assetIds.has(suppliedId)) {
      throw new Error(`Unexpected recovered asset key supplied: ${suppliedId}.`);
    }
  }

  const trusteeRecords = policy.trustee_ids.map((trusteeId) => {
    const trustee = allTrustees.find((item) => item.id === trusteeId);

    if (!trustee) {
      throw new Error(`Assigned trustee ${trusteeId} could not be found.`);
    }
    if (!trustee.active) {
      throw new Error(`Trustee ${trusteeId} is inactive.`);
    }
    if (!trustee.public_key) {
      throw new Error(`Trustee ${trusteeId} has no registered X25519 public key.`);
    }

    return {
      id: trustee.id,
      public_key: trustee.public_key,
    };
  }) satisfies RotationTrustee[];

  // The original AES keys stay in browser memory. Only encrypted
  // envelopes and SHA-256 commitments are placed in this request.
  const rotationRequest = await createPolicyRotationRequest({
    expectedEpoch: policy.epoch,
    policyId: policy.id,
    trustees: trusteeRecords,
    assets: assets.map((asset) => ({
      assetId: asset.id,
      aesKeyBytes: input.recoveredAssetKeys.get(asset.id)!,
      threshold: asset.threshold,
    })),
  });

  // Phase 1: backend validates DB state and current on-chain state.
  const prepared = await authApiRequest<PreparedOnchainRotation>(
    `/api/policies/${encodeURIComponent(policy.id)}/rotate-shares/onchain/prepare`,
    {
      method: "POST",
      body: JSON.stringify(rotationRequest),
    },
  );

  if (
    prepared.policy_id !== policy.id ||
    prepared.previous_epoch !== policy.epoch ||
    prepared.new_epoch !== policy.epoch + 1 ||
    prepared.function_signature !==
      "rotatePolicyAssetCommitments(string,uint64,uint64,string[],address[],bytes32[][])"
  ) {
    throw new Error("The backend returned an invalid on-chain rotation payload.");
  }

  if (
    prepared.asset_ids.length !== assets.length ||
    prepared.trustee_wallets.length !== trusteeRecords.length ||
    prepared.new_commitments.length !== assets.length ||
    prepared.new_commitments.some(
      (row) => row.length !== trusteeRecords.length,
    )
  ) {
    throw new Error("The prepared on-chain commitment matrix is incomplete.");
  }

  const provider = new BrowserProvider(window.ethereum);
  const network = await provider.getNetwork();

  if (Number(network.chainId) !== prepared.chain_id) {
    throw new Error(
      `Switch MetaMask to chain ID ${prepared.chain_id} before rotating shares.`,
    );
  }

  const signer = await provider.getSigner();
  const signerAddress = await signer.getAddress();

  if (
    signerAddress.toLowerCase() !== prepared.contract_owner.toLowerCase()
  ) {
    throw new Error(
      `The connected wallet is not the DeadDrop contract owner. Connect ${prepared.contract_owner} in MetaMask.`,
    );
  }

  const contract = new Contract(
    prepared.contract_address,
    rotationContractAbi,
    signer,
  );

  // Phase 2: one atomic transaction updates the policy and all assets.
  const transaction = await contract.rotatePolicyAssetCommitments(
    policy.id,
    prepared.previous_epoch,
    prepared.new_epoch,
    prepared.asset_ids,
    prepared.trustee_wallets,
    prepared.new_commitments,
  );

  const receipt = await transaction.wait();

  if (!receipt || receipt.status !== 1) {
    throw new Error(
      `The on-chain rotation transaction failed. Transaction hash: ${transaction.hash}`,
    );
  }

  // Phase 3: backend verifies the exact mined call and every on-chain
  // asset epoch/commitment before committing the database projection.
  let result: PolicyRotationResult;

  try {
    result = await authApiRequest<PolicyRotationResult>(
      `/api/policies/${encodeURIComponent(policy.id)}/rotate-shares/onchain/finalize`,
      {
        method: "POST",
        body: JSON.stringify({
          ...rotationRequest,
          transaction_hash: transaction.hash,
        }),
      },
    );
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown backend error";

    throw new Error(
      `The blockchain transaction succeeded (${transaction.hash}), but backend finalization failed: ${message}. Do not submit another rotation. Reconcile the database with the mined transaction first.`,
    );
  }

  if (
    result.policy_id !== policy.id ||
    result.previous_epoch !== policy.epoch ||
    result.new_epoch !== policy.epoch + 1 ||
    result.updated_asset_count !== assets.length ||
    result.inserted_share_count !== assets.length * trusteeRecords.length ||
    result.verified !== true
  ) {
    throw new Error(
      `The transaction was mined (${transaction.hash}), but the backend returned an unexpected verification result. Do not rotate again until this transaction is reconciled.`,
    );
  }

  return {
    ...result,
    transaction: {
      ...(result.transaction ?? {}),
      hash: transaction.hash,
    },
  };
}