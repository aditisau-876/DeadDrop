import { useEffect, useState, type FormEvent } from "react";
import {
  BrowserProvider,
  Contract,
  keccak256,
  randomBytes,
} from "ethers";

import { Page } from "../components/Page";
import { authApiRequest as apiRequest } from "../lib/authApi";

import {
  decryptTrusteeShare,
  verifyShareCommitment,
  reconstructSecretFromShares,
  decryptProtectedAsset,
} from "../lib/crypto/recovery";

import {
  signShareReleaseChallenge,
  type ShareReleaseChallenge,
} from "../lib/crypto/shareRelease";
import { storeRecoveredAssetKey } from "../lib/crypto/rotationKeyVault";

interface ReleasedShare {
  recovery_id: string;
  asset_id: string;
  policy_id: string;
  trustee_id: string;
  epoch: number;
  encrypted_share: string;
  commitment: string;
  message: string;
}

interface VerifiedShare {
  recoveryId: string;
  assetId: string;
  trusteeId: string;
  policyId: string;
  epoch: number;
  value: string;
}

interface ChallengeRequest {
  recovery_id: string;
  asset_id: string;
  trustee_id: string;
}

interface PolicyOption {
  id: string;
  name: string;
  active: boolean;
  policy_tree: {
    type?: string;
    threshold?: number;
    children?: Array<{
      type?: string;
      trustee_id?: string;
    }>;
  } | null;
}

interface CreatedRecovery {
  id: string;
  policy_id: string;
  status: string;
}

interface RecoveryRegistrationPayload {
  recovery_id: string;
  policy_id: string;
  incident_hash: string;
  expires_at: number;
  chain_id: number;
  contract_address: string;
}

interface EncryptedAssetPayload {
  id: string;
  policy_id: string;
  ciphertext: string;
  nonce: string;
  aad: string | null;
  epoch: number;
  threshold: number;
}

interface ExecutionPayload {
  chain_id: number;
  contract_address: string;
  ready: boolean;
}

interface RecoveryVerification {
  verified: boolean;
}

const recoveryContractAbi = [
  "function requestRecovery(string recoveryId,string policyId,bytes32 incidentHash,uint64 expiresAt)",
  "function executeRecovery(string recoveryId,bytes32 artifactHash)",
];

export function Recovery() {
  const [policies, setPolicies] = useState<PolicyOption[]>([]);
  const [selectedPolicyId, setSelectedPolicyId] = useState("");

  const [recoveryReason, setRecoveryReason] = useState("");
  const [recoveryId, setRecoveryId] = useState("");
  const [assetId, setAssetId] = useState("");
  const [trusteeId, setTrusteeId] = useState("");
  const [privateKey, setPrivateKey] = useState("");

  const [assetMetadata, setAssetMetadata] =
    useState<EncryptedAssetPayload | null>(null);

  const [assetLoading, setAssetLoading] = useState(false);
  const [assetError, setAssetError] = useState("");

  const [verifiedShares, setVerifiedShares] = useState<
    VerifiedShare[]
  >([]);

  const [creatingRecovery, setCreatingRecovery] = useState(false);
  const [reconstructing, setReconstructing] = useState(false);
  const [loading, setLoading] = useState(false);

  const [recoveredContent, setRecoveredContent] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // The threshold is always obtained from the protected asset.
  const threshold = assetMetadata?.threshold ?? null;

  // Only count shares belonging to the active recovery and asset.
  const activeVerifiedShares = verifiedShares.filter(
    (share) =>
      share.recoveryId === recoveryId.trim() &&
      share.assetId === assetId.trim(),
  );

  const collectedCount = activeVerifiedShares.length;

  const readyForReconstruction =
    threshold !== null &&
    collectedCount >= threshold;

  // Load active supported policies.
  useEffect(() => {
    let mounted = true;

    apiRequest<PolicyOption[]>("/api/policies")
      .then((items) => {
        if (!mounted) return;

        const activeItems = items.filter(
          (item) =>
            item.active &&
            item.policy_tree?.type === "THRESHOLD" &&
            Array.isArray(item.policy_tree.children) &&
            item.policy_tree.children.every(
              (child) => child.type === "LEAF",
            ),
        );

        setPolicies(activeItems);

        if (activeItems.length > 0) {
          setSelectedPolicyId(activeItems[0].id);
        }
      })
      .catch((err: unknown) => {
        if (!mounted) return;

        setError(
          err instanceof Error
            ? err.message
            : "Unable to load policies.",
        );
      });

    return () => {
      mounted = false;
    };
  }, []);

  // Fetch the real asset threshold whenever the asset ID changes.
  useEffect(() => {
    let mounted = true;

    const id = assetId.trim();

    setAssetMetadata(null);
    setAssetError("");

    if (!id) {
      setAssetLoading(false);
      return;
    }

    setAssetLoading(true);

    apiRequest<EncryptedAssetPayload>(
      `/api/assets/${encodeURIComponent(id)}/encrypted-payload`,
    )
      .then((payload) => {
        if (!mounted) return;

        if (payload.id !== id) {
          throw new Error(
            "The backend returned metadata for a different asset.",
          );
        }

        if (
          !Number.isInteger(payload.threshold) ||
          payload.threshold < 2
        ) {
          throw new Error(
            "The protected asset has an invalid cryptographic threshold.",
          );
        }

        if (
          !Number.isInteger(payload.epoch) ||
          payload.epoch < 1
        ) {
          throw new Error(
            "The protected asset has an invalid epoch.",
          );
        }

        if (
          !payload.policy_id ||
          !payload.ciphertext ||
          !payload.nonce
        ) {
          throw new Error(
            "The protected asset metadata is incomplete.",
          );
        }

        setAssetMetadata(payload);
      })
      .catch((err: unknown) => {
        if (!mounted) return;

        setAssetMetadata(null);
        setAssetError(
          err instanceof Error
            ? err.message
            : "Unable to load protected asset metadata.",
        );
      })
      .finally(() => {
        if (mounted) {
          setAssetLoading(false);
        }
      });

    return () => {
      mounted = false;
    };
  }, [assetId]);

  function clearRecoveryData() {
    setVerifiedShares([]);
    setRecoveredContent("");
    setPrivateKey("");
    setTrusteeId("");
  }

  function handleRecoveryIdChange(value: string) {
    if (value.trim() !== recoveryId.trim()) {
      clearRecoveryData();
      setError("");
      setSuccess("");
    }

    setRecoveryId(value);
  }

  function handleAssetIdChange(value: string) {
    if (value.trim() !== assetId.trim()) {
      clearRecoveryData();
      setError("");
      setSuccess("");
    }

    setAssetId(value);
  }

  async function handleCreateRecovery(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    setError("");
    setSuccess("");

    if (!selectedPolicyId || !recoveryReason.trim()) {
      setError(
        "Select a policy and enter a recovery reason.",
      );
      return;
    }

    setCreatingRecovery(true);

    try {
      const chainPolicy = await apiRequest<{
        blockchain: { exists: boolean };
        synchronized: boolean;
      }>(
        `/api/blockchain/contract/policies/${encodeURIComponent(
          selectedPolicyId,
        )}`,
      );

      if (
        !chainPolicy.blockchain.exists ||
        !chainPolicy.synchronized
      ) {
        throw new Error(
          "Register and verify this policy on-chain before creating a recovery request.",
        );
      }

      const incidentHash = keccak256(randomBytes(32));

      const created = await apiRequest<CreatedRecovery>(
        "/api/recovery",
        {
          method: "POST",
          body: JSON.stringify({
            policy_id: selectedPolicyId,
            reason: recoveryReason.trim(),
            incident_hash: incidentHash,
          }),
        },
      );

      setRecoveryId(created.id);
      clearRecoveryData();

      if (!window.ethereum) {
        throw new Error(
          `Recovery ${created.id} was created in the database. MetaMask was not detected. Connect it and retry the on-chain registration.`,
        );
      }

      const payload =
        await apiRequest<RecoveryRegistrationPayload>(
          `/api/blockchain/registration/recoveries/${encodeURIComponent(
            created.id,
          )}`,
        );

      const provider = new BrowserProvider(window.ethereum);
      const network = await provider.getNetwork();

      if (Number(network.chainId) !== payload.chain_id) {
        throw new Error(
          `Recovery ${created.id} exists in the database. Switch MetaMask to chain ID ${payload.chain_id} and retry.`,
        );
      }

      const signer = await provider.getSigner();

      const contract = new Contract(
        payload.contract_address,
        recoveryContractAbi,
        signer,
      );

      const tx = await contract.requestRecovery(
        payload.recovery_id,
        payload.policy_id,
        payload.incident_hash,
        payload.expires_at,
      );

      const receipt = await tx.wait();

      if (!receipt || receipt.status !== 1) {
        throw new Error(
          "The on-chain recovery request transaction failed.",
        );
      }

      const verification =
        await apiRequest<RecoveryVerification>(
          `/api/blockchain/registration/recoveries/${encodeURIComponent(
            created.id,
          )}/verify`,
          {
            method: "POST",
            body: JSON.stringify({
              transaction_hash: tx.hash,
            }),
          },
        );

      if (!verification.verified) {
        throw new Error(
          "The transaction was mined, but backend verification failed.",
        );
      }

      setSuccess(
        `Recovery request created and verified on-chain. Recovery ID: ${created.id}. Transaction: ${tx.hash}`,
      );

      setRecoveryReason("");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to create the recovery request.",
      );
    } finally {
      setCreatingRecovery(false);
    }
  }

  async function handleRegisterExistingRecovery() {
    setError("");
    setSuccess("");

    if (!recoveryId.trim()) {
      setError("Enter the database recovery ID first.");
      return;
    }

    setCreatingRecovery(true);

    try {
      if (!window.ethereum) {
        throw new Error("MetaMask was not detected.");
      }

      const payload =
        await apiRequest<RecoveryRegistrationPayload>(
          `/api/blockchain/registration/recoveries/${encodeURIComponent(
            recoveryId.trim(),
          )}`,
        );

      const provider = new BrowserProvider(window.ethereum);
      const network = await provider.getNetwork();

      if (Number(network.chainId) !== payload.chain_id) {
        throw new Error(
          `Switch MetaMask to chain ID ${payload.chain_id}.`,
        );
      }

      const signer = await provider.getSigner();

      const contract = new Contract(
        payload.contract_address,
        recoveryContractAbi,
        signer,
      );

      const tx = await contract.requestRecovery(
        payload.recovery_id,
        payload.policy_id,
        payload.incident_hash,
        payload.expires_at,
      );

      const receipt = await tx.wait();

      if (!receipt || receipt.status !== 1) {
        throw new Error(
          "The on-chain recovery request transaction failed.",
        );
      }

      const verification =
        await apiRequest<RecoveryVerification>(
          `/api/blockchain/registration/recoveries/${encodeURIComponent(
            recoveryId.trim(),
          )}/verify`,
          {
            method: "POST",
            body: JSON.stringify({
              transaction_hash: tx.hash,
            }),
          },
        );

      if (!verification.verified) {
        throw new Error(
          "The transaction was mined, but backend verification failed.",
        );
      }

      setSuccess(
        `Existing recovery request registered and verified on-chain. Transaction: ${tx.hash}`,
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to register the existing recovery request.",
      );
    } finally {
      setCreatingRecovery(false);
    }
  }

  async function handleReleaseShare(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    setError("");
    setSuccess("");

    if (
      !recoveryId.trim() ||
      !assetId.trim() ||
      !trusteeId.trim()
    ) {
      setError(
        "Enter the recovery, asset, and trustee IDs.",
      );
      return;
    }

    if (!assetMetadata || assetLoading) {
      setError(
        "Wait for the protected asset metadata to load before collecting shares.",
      );
      return;
    }

    if (assetError) {
      setError(assetError);
      return;
    }

    if (!privateKey.trim()) {
      setError(
        "Enter the trustee's X25519 private key.",
      );
      return;
    }

    if (
      activeVerifiedShares.some(
        (share) => share.trusteeId === trusteeId.trim(),
      )
    ) {
      setError(
        "A verified share from this trustee has already been collected.",
      );
      return;
    }

    setLoading(true);

    try {
      const request: ChallengeRequest = {
        recovery_id: recoveryId.trim(),
        asset_id: assetId.trim(),
        trustee_id: trusteeId.trim(),
      };

      // Step 1: Request a one-time release challenge.
      const challenge =
        await apiRequest<ShareReleaseChallenge>(
          "/api/recovery-packages/challenge",
          {
            method: "POST",
            body: JSON.stringify(request),
          },
        );

      // Step 2: Ask the registered trustee wallet to sign.
      const signed =
        await signShareReleaseChallenge(challenge);

      // Step 3: Submit the signed challenge.
      const released = await apiRequest<ReleasedShare>(
        "/api/recovery-packages/release",
        {
          method: "POST",
          body: JSON.stringify({
            challenge_id: signed.challengeId,
            nonce: signed.nonce,
            recovery_id: request.recovery_id,
            asset_id: request.asset_id,
            trustee_id: request.trustee_id,
            signature: signed.signature,
          }),
        },
      );

      // Step 4: Check that the returned share belongs to
      // the exact recovery and asset requested.
      if (
        released.recovery_id !== request.recovery_id ||
        released.asset_id !== request.asset_id ||
        released.trustee_id !== request.trustee_id
      ) {
        throw new Error(
          "The backend returned a share for a different recovery, asset, or trustee.",
        );
      }

      if (
        released.policy_id !== assetMetadata.policy_id ||
        released.epoch !== assetMetadata.epoch
      ) {
        throw new Error(
          "The released share does not match the protected asset policy and epoch.",
        );
      }

      // Step 5: Decrypt the share locally.
      const decrypted = await decryptTrusteeShare(
        released.encrypted_share,
        privateKey.trim(),
        {
          policyId: released.policy_id,
          trusteeId: released.trustee_id,
          epoch: released.epoch,
        },
      );

      if (
        decrypted.trusteeId !== request.trustee_id ||
        decrypted.policyId !== assetMetadata.policy_id ||
        decrypted.epoch !== assetMetadata.epoch
      ) {
        throw new Error(
          "The decrypted share metadata does not match the requested trustee and asset.",
        );
      }

      // Step 6: Verify the share commitment locally.
      const commitmentValid =
        await verifyShareCommitment(
          decrypted,
          released.commitment,
        );

      if (!commitmentValid) {
        throw new Error(
          "Share commitment verification failed. This share will not be accepted.",
        );
      }

      // Step 7: Store the verified share in browser memory.
      setVerifiedShares((current) => {
        const alreadyExists = current.some(
          (share) =>
            share.recoveryId === request.recovery_id &&
            share.assetId === request.asset_id &&
            share.trusteeId === decrypted.trusteeId,
        );

        if (alreadyExists) {
          return current;
        }

        return [
          ...current,
          {
            recoveryId: request.recovery_id,
            assetId: request.asset_id,
            trusteeId: decrypted.trusteeId,
            policyId: decrypted.policyId,
            epoch: decrypted.epoch,
            value: decrypted.value,
          },
        ];
      });

      setSuccess(
        `Trustee ${decrypted.trusteeId}: encrypted share decrypted and commitment verified.`,
      );

      setPrivateKey("");
      setTrusteeId("");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Share release failed.",
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleReconstructAndExecute() {
    setError("");
    setSuccess("");
    setRecoveredContent("");

    if (!recoveryId.trim() || !assetId.trim()) {
      setError(
        "Enter the recovery request ID and protected asset ID first.",
      );
      return;
    }

    if (assetLoading || !assetMetadata) {
      setError(
        "Protected asset metadata has not finished loading.",
      );
      return;
    }

    if (!readyForReconstruction || threshold === null) {
      setError(
        `Collect at least ${threshold ?? "the required number of"} verified shares first.`,
      );
      return;
    }

    setReconstructing(true);

    try {
      // Re-fetch the authoritative asset metadata before reconstruction.
      const encryptedPayload =
        await apiRequest<EncryptedAssetPayload>(
          `/api/assets/${encodeURIComponent(
            assetId.trim(),
          )}/encrypted-payload`,
        );

      if (encryptedPayload.id !== assetId.trim()) {
        throw new Error(
          "The backend returned metadata for a different asset.",
        );
      }

      if (
        encryptedPayload.threshold !== assetMetadata.threshold ||
        encryptedPayload.policy_id !== assetMetadata.policy_id ||
        encryptedPayload.epoch !== assetMetadata.epoch
      ) {
        throw new Error(
          "The protected asset metadata changed. Reload the asset and collect its shares again.",
        );
      }

      const selected = activeVerifiedShares.slice(
        0,
        encryptedPayload.threshold,
      );

      if (selected.length < encryptedPayload.threshold) {
        throw new Error(
          `You need ${encryptedPayload.threshold} verified shares for this recovery and asset.`,
        );
      }

      const first = selected[0];

      if (
        selected.some(
          (share) =>
            share.recoveryId !== recoveryId.trim() ||
            share.assetId !== assetId.trim() ||
            share.policyId !== encryptedPayload.policy_id ||
            share.epoch !== encryptedPayload.epoch,
        )
      ) {
        throw new Error(
          "Collected shares do not belong to the same recovery, asset, policy, and epoch.",
        );
      }

      const uniqueTrustees = new Set(
        selected.map((share) => share.trusteeId),
      );

      if (uniqueTrustees.size !== selected.length) {
        throw new Error(
          "Duplicate trustee shares cannot be used for reconstruction.",
        );
      }

      if (
        first.policyId !== encryptedPayload.policy_id ||
        first.epoch !== encryptedPayload.epoch
      ) {
        throw new Error(
          "Collected shares do not match the selected protected asset.",
        );
      }

      // Reconstruct the AES key from the verified Shamir shares.
      const aesKey = reconstructSecretFromShares(
        selected.map((share) => share.value),
      );

      // Decrypt the protected asset locally.
      const plaintextBytes = await decryptProtectedAsset(
        encryptedPayload,
        aesKey,
      );

      const plaintext = new TextDecoder().decode(
        plaintextBytes,
      );

      // Keep the authenticated AES key only in this browser tab so an
      // owner can later rotate every asset under the same policy.
      // The key is never sent to the backend or persisted to storage.
      storeRecoveredAssetKey(
        encryptedPayload.policy_id,
        encryptedPayload.id,
        encryptedPayload.epoch,
        aesKey,
      );

      setRecoveredContent(plaintext);

      // Only finalize on-chain after local reconstruction
      // and AES-GCM authentication have succeeded.
      if (!window.ethereum) {
        throw new Error(
          "The asset was decrypted locally, but MetaMask is not available to finalize on-chain execution.",
        );
      }

      const execution =
        await apiRequest<ExecutionPayload>(
          `/api/blockchain/registration/recoveries/${encodeURIComponent(
            recoveryId.trim(),
          )}/execute`,
        );

      if (!execution.ready) {
        throw new Error(
          "The backend reports that this recovery is not ready for on-chain execution.",
        );
      }

      const provider = new BrowserProvider(window.ethereum);
      const network = await provider.getNetwork();

      if (Number(network.chainId) !== execution.chain_id) {
        throw new Error(
          `Asset decrypted locally. Switch MetaMask to chain ID ${execution.chain_id} to finalize recovery.`,
        );
      }

      const signer = await provider.getSigner();

      const contract = new Contract(
        execution.contract_address,
        recoveryContractAbi,
        signer,
      );

      const artifactHash = keccak256(plaintextBytes);

      const tx = await contract.executeRecovery(
        recoveryId.trim(),
        artifactHash,
      );

      const receipt = await tx.wait();

      if (!receipt || receipt.status !== 1) {
        throw new Error(
          "Asset decrypted locally, but the on-chain execution transaction failed.",
        );
      }

      const verification =
        await apiRequest<RecoveryVerification>(
          `/api/blockchain/registration/recoveries/${encodeURIComponent(
            recoveryId.trim(),
          )}/execute/verify`,
          {
            method: "POST",
            body: JSON.stringify({
              transaction_hash: tx.hash,
              artifact_hash: artifactHash,
            }),
          },
        );

      if (!verification.verified) {
        throw new Error(
          "The transaction was mined, but backend execution verification failed.",
        );
      }

      setSuccess(
        `Asset reconstructed and decrypted locally. On-chain recovery execution verified. Transaction: ${tx.hash}`,
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Reconstruction or on-chain execution failed.",
      );
    } finally {
      setReconstructing(false);
    }
  }

  function clearCollectedShares() {
    setVerifiedShares([]);
    setRecoveredContent("");
    setError("");
    setSuccess("");
  }

  return (
    <Page
      title="Emergency Recovery"
      sub="Governance approval, trustee authorization, and local cryptographic verification."
    >
      <section className="card recovery-intro">
        <div className="recovery-heading">
          <div>
            <small>RECOVERY PROTOCOL</small>
            <h3>Recover a protected asset</h3>
          </div>

          <span className="recovery-indicator">
            CLIENT-SIDE VERIFICATION
          </span>
        </div>

        <p>
          Collect encrypted shares from authorized trustees.
          Each share is decrypted locally and checked against
          its SHA-256 commitment before it is accepted.
        </p>
      </section>

      <section className="card">
        <small className="eyebrow">OWNER WORKFLOW</small>
        <h3>Create an on-chain recovery request</h3>

        <p className="muted">
          This creates the database request first, then asks
          MetaMask to create the matching timelocked request
          on the DeadDrop contract. Keep the returned recovery ID.
        </p>

        <form
          className="admin-form"
          onSubmit={handleCreateRecovery}
        >
          <label>
            Recovery policy

            <select
              required
              value={selectedPolicyId}
              onChange={(event) =>
                setSelectedPolicyId(event.target.value)
              }
            >
              {policies.length === 0 && (
                <option value="">
                  No active policies available
                </option>
              )}

              {policies.map((policy) => (
                <option key={policy.id} value={policy.id}>
                  {policy.name}
                </option>
              ))}
            </select>
          </label>

          <label>
            Reason for recovery

            <textarea
              required
              maxLength={1000}
              rows={3}
              value={recoveryReason}
              onChange={(event) =>
                setRecoveryReason(event.target.value)
              }
              placeholder="Explain why access to the protected asset is needed."
            />
          </label>

          <button
            type="submit"
            disabled={
              creatingRecovery || policies.length === 0
            }
          >
            {creatingRecovery
              ? "CREATING REQUEST…"
              : "CREATE & REGISTER RECOVERY"}
          </button>
        </form>
      </section>

      <section className="card">
        <h3>Recovery context</h3>

        <div className="recovery-fields">
          <label>
            <span>Recovery request ID</span>

            <input
              value={recoveryId}
              onChange={(event) =>
                handleRecoveryIdChange(event.target.value)
              }
              placeholder="Enter recovery ID"
              required
            />
          </label>

          <button
            type="button"
            disabled={
              creatingRecovery || !recoveryId.trim()
            }
            onClick={() =>
              void handleRegisterExistingRecovery()
            }
          >
            {creatingRecovery
              ? "REGISTERING…"
              : "RETRY ON-CHAIN REGISTRATION"}
          </button>

          <label>
            <span>Protected asset ID</span>

            <input
              value={assetId}
              onChange={(event) =>
                handleAssetIdChange(event.target.value)
              }
              placeholder="Enter asset ID"
              required
            />
          </label>

          <div className="recovery-threshold">
            <span>Required cryptographic threshold</span>

            {assetLoading ? (
              <strong>Loading asset metadata…</strong>
            ) : assetError ? (
              <strong className="recovery-error">
                Unable to load threshold
              </strong>
            ) : threshold !== null ? (
              <strong>
                {threshold} verified shares required
              </strong>
            ) : (
              <strong>
                Enter a protected asset ID
              </strong>
            )}
          </div>
        </div>

        {assetError && (
          <div className="recovery-alert recovery-error">
            {assetError}
          </div>
        )}

        {assetMetadata && (
          <div className="recovery-alert recovery-success">
            Asset metadata verified. Policy:{" "}
            {assetMetadata.policy_id} · Epoch:{" "}
            {assetMetadata.epoch} · Threshold:{" "}
            {assetMetadata.threshold}
          </div>
        )}

        <p className="recovery-note">
          The threshold is retrieved directly from the protected
          asset's backend metadata. It cannot be manually changed
          in this recovery screen.
        </p>
      </section>

      <section className="card">
        <h3>Authorize and collect a trustee share</h3>

        <form
          className="recovery-form"
          onSubmit={handleReleaseShare}
        >
          <label>
            <span>Trustee ID</span>

            <input
              value={trusteeId}
              onChange={(event) =>
                setTrusteeId(event.target.value)
              }
              placeholder="Enter registered trustee ID"
              required
            />
          </label>

          <label>
            <span>Trustee X25519 private key</span>

            <input
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={privateKey}
              onChange={(event) =>
                setPrivateKey(event.target.value)
              }
              placeholder="Paste trustee's Base64 private key"
              required
            />
          </label>

          <p className="recovery-note">
            This is the trustee's X25519 decryption key,
            not the MetaMask wallet private key or seed phrase.
            It is used locally and is not submitted to FastAPI.
          </p>

          <button
            type="submit"
            disabled={
              loading ||
              readyForReconstruction ||
              !assetMetadata ||
              assetLoading
            }
          >
            {loading
              ? "Processing secure release..."
              : "Authorize and verify share"}
          </button>
        </form>

        {error && (
          <div className="recovery-alert recovery-error">
            {error}
          </div>
        )}

        {success && (
          <div className="recovery-alert recovery-success">
            {success}
          </div>
        )}
      </section>

      <section className="card">
        <div className="recovery-heading">
          <div>
            <small>CRYPTOGRAPHIC QUORUM</small>
            <h3>Verified share collection</h3>
          </div>

          <strong className="recovery-count">
            {collectedCount} / {threshold ?? "—"}
          </strong>
        </div>

        <div className="recovery-progress">
          <div
            style={{
              width:
                threshold !== null
                  ? `${Math.min(
                      100,
                      (collectedCount / threshold) * 100,
                    )}%`
                  : "0%",
            }}
          />
        </div>

        {activeVerifiedShares.length === 0 ? (
          <p className="recovery-note">
            No verified shares have been collected yet.
          </p>
        ) : (
          <div className="recovery-share-list">
            {activeVerifiedShares.map((share) => (
              <div
                className="recovery-share-item"
                key={`${share.recoveryId}-${share.assetId}-${share.trusteeId}`}
              >
                <div>
                  <strong>{share.trusteeId}</strong>

                  <small>
                    Epoch {share.epoch} · Commitment verified
                  </small>
                </div>

                <span className="ok">Verified</span>
              </div>
            ))}
          </div>
        )}

        {readyForReconstruction && (
          <div className="recovery-alert recovery-success">
            The configured number of shares has been collected
            and individually verified. You can now reconstruct
            the AES key and decrypt the asset locally.
          </div>
        )}

        <button
          type="button"
          onClick={() =>
            void handleReconstructAndExecute()
          }
          disabled={
            !readyForReconstruction ||
            reconstructing ||
            loading
          }
        >
          {reconstructing
            ? "RECONSTRUCTING & FINALIZING…"
            : "RECONSTRUCT, DECRYPT & FINALIZE"}
        </button>

        {recoveredContent && (
          <div className="recovery-result">
            <small className="eyebrow">
              LOCALLY DECRYPTED ASSET
            </small>

            <textarea
              readOnly
              rows={8}
              value={recoveredContent}
            />
          </div>
        )}

        <button
          type="button"
          className="danger"
          onClick={clearCollectedShares}
          disabled={loading || collectedCount === 0}
        >
          Clear locally collected shares
        </button>
      </section>
    </Page>
  );
}