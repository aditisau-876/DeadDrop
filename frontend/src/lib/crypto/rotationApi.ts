
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

export interface PolicyRotationResult {
  policy_id: string;
  previous_epoch: number;
  new_epoch: number;
  new_policy_version: number;
  updated_asset_count: number;
  inserted_share_count: number;
  message: string;
}

export interface RotatePolicyInput {
  policyId: string;

  /**
   * Map of asset ID to its recovered original AES-256 key.
   * Keys must be reconstructed locally through the authorized
   * trustee recovery process.
   */
  recoveredAssetKeys: Map<string, Uint8Array>;
}

/**
 * Rotate all encrypted trustee shares for a policy.
 *
 * The AES keys are used only in browser memory to generate
 * fresh Shamir shares. They are never sent to the backend.
 *
 * The backend receives only encrypted shares and commitments.
 */
export async function rotatePolicyShares(
  input: RotatePolicyInput,
): Promise<PolicyRotationResult> {
  if (!input.policyId.trim()) {
    throw new Error("Policy ID is required.");
  }

  if (input.recoveredAssetKeys.size === 0) {
    throw new Error(
      "No recovered asset keys were supplied.",
    );
  }

  // 1. Load the current policy.
  const policy =
    await authApiRequest<PolicyRotationDetails>(
      `/api/policies/${encodeURIComponent(input.policyId)}`,
    );

  if (!policy.active) {
    throw new Error(
      "Inactive policies cannot rotate shares.",
    );
  }

  if (
    !Number.isInteger(policy.epoch) ||
    policy.epoch < 1
  ) {
    throw new Error("The policy has an invalid epoch.");
  }

  if (
    !Array.isArray(policy.trustee_ids) ||
    policy.trustee_ids.length < 2
  ) {
    throw new Error(
      "At least two assigned trustees are required.",
    );
  }

  if (
    new Set(policy.trustee_ids).size !==
    policy.trustee_ids.length
  ) {
    throw new Error(
      "The policy contains duplicate trustee assignments.",
    );
  }

  // 2. Load all protected assets and trustees.
  const [allAssets, allTrustees] = await Promise.all([
    authApiRequest<RotationAsset[]>("/api/assets"),
    authApiRequest<RotationTrusteeRecord[]>("/api/trustees"),
  ]);

  const assets = allAssets.filter(
    (asset) => asset.policy_id === policy.id,
  );

  if (assets.length === 0) {
    throw new Error(
      "This policy has no protected assets to rotate.",
    );
  }

  // 3. Confirm that every asset is in the current epoch.
  for (const asset of assets) {
    if (asset.epoch !== policy.epoch) {
      throw new Error(
        `Asset ${asset.id} is not synchronized with policy epoch ${policy.epoch}.`,
      );
    }

    if (
      !Number.isInteger(asset.threshold) ||
      asset.threshold < 2 ||
      asset.threshold > policy.trustee_ids.length
    ) {
      throw new Error(
        `Asset ${asset.id} has an invalid recovery threshold.`,
      );
    }
  }

  // 4. Ensure the caller supplied a recovered key for
  // every protected asset, and no unrelated asset keys.
  const assetIds = new Set(
    assets.map((asset) => asset.id),
  );

  for (const assetId of assetIds) {
    const key = input.recoveredAssetKeys.get(assetId);

    if (!key || key.length !== 32) {
      throw new Error(
        `A valid recovered AES-256 key is missing for asset ${assetId}.`,
      );
    }
  }

  for (const suppliedId of input.recoveredAssetKeys.keys()) {
    if (!assetIds.has(suppliedId)) {
      throw new Error(
        `Unexpected asset key supplied: ${suppliedId}.`,
      );
    }
  }

  // 5. Resolve exactly the trustees assigned to this policy.
  const trusteeRecords = policy.trustee_ids.map(
    (trusteeId) => {
      const trustee = allTrustees.find(
        (item) => item.id === trusteeId,
      );

      if (!trustee) {
        throw new Error(
          `Assigned trustee ${trusteeId} could not be found.`,
        );
      }

      if (!trustee.active) {
        throw new Error(
          `Trustee ${trusteeId} is inactive.`,
        );
      }

      if (!trustee.public_key) {
        throw new Error(
          `Trustee ${trusteeId} has no registered public key.`,
        );
      }

      return {
        id: trustee.id,
        public_key: trustee.public_key,
      };
    },
  ) satisfies RotationTrustee[];

  // 6. Generate fresh shares locally for every asset.
  const rotationRequest = await createPolicyRotationRequest({
    expectedEpoch: policy.epoch,
    policyId: policy.id,
    trustees: trusteeRecords,
    assets: assets.map((asset) => ({
      assetId: asset.id,
      aesKeyBytes: input.recoveredAssetKeys.get(
        asset.id,
      )!,
      threshold: asset.threshold,
    })),
  });

  // 7. Submit only encrypted shares and commitments.
  // The backend performs the complete epoch update atomically.
  const result =
    await authApiRequest<PolicyRotationResult>(
      `/api/policies/${encodeURIComponent(policy.id)}/rotate-shares`,
      {
        method: "POST",
        body: JSON.stringify(rotationRequest),
      },
    );

  // 8. Verify the returned result.
  if (
    result.policy_id !== policy.id ||
    result.previous_epoch !== policy.epoch ||
    result.new_epoch !== policy.epoch + 1 ||
    result.updated_asset_count !== assets.length ||
    result.inserted_share_count !==
      assets.length * trusteeRecords.length
  ) {
    throw new Error(
      "The backend returned an unexpected rotation result. Refresh the policy and asset records before continuing.",
    );
  }

  return result;
}
