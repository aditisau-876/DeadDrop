import { useState } from "react";
import { Page } from "../components/Page";
import { authApiRequest as apiRequest } from "../lib/authApi";
import {
  decryptTrusteeShare,
  verifyShareCommitment,
} from "../lib/crypto/recovery";

import {
  signShareReleaseChallenge,
  type ShareReleaseChallenge,
} from "../lib/crypto/shareRelease";


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


export function Recovery() {
  const [recoveryId, setRecoveryId] = useState("");
  const [assetId, setAssetId] = useState("");
  const [trusteeId, setTrusteeId] = useState("");

  const [privateKey, setPrivateKey] = useState("");
  const [threshold, setThreshold] = useState(3);

  const [verifiedShares, setVerifiedShares] = useState<
    VerifiedShare[]
  >([]);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const collectedCount = verifiedShares.length;

  const readyForReconstruction =
    collectedCount >= threshold;


  async function handleReleaseShare(
    event: React.FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    setError("");
    setSuccess("");

    if (!recoveryId.trim() || !assetId.trim() || !trusteeId.trim()) {
      setError("Enter the recovery, asset, and trustee IDs.");
      return;
    }

    if (!privateKey.trim()) {
      setError("Enter the trustee's X25519 private key.");
      return;
    }

    if (
      verifiedShares.some(
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
      const challenge = await apiRequest<ShareReleaseChallenge>(
        "/api/recovery-packages/challenge",
        {
          method: "POST",
          body: JSON.stringify(request),
        },
      );

      // Step 2: Ask the registered trustee wallet to sign.
      const signed = await signShareReleaseChallenge(
        challenge,
      );

      // Step 3: Submit the signature and challenge nonce.
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

      // Step 4: Decrypt the share locally.
      const decrypted = await decryptTrusteeShare(
        released.encrypted_share,
        privateKey.trim(),
        {
          policyId: released.policy_id,
          trusteeId: released.trustee_id,
          epoch: released.epoch,
        },
      );

      // Step 5: Verify the share commitment locally.
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

      // Step 6: Keep the verified share in browser memory.
      setVerifiedShares((current) => [
        ...current,
        {
          trusteeId: decrypted.trusteeId,
          policyId: decrypted.policyId,
          epoch: decrypted.epoch,
          value: decrypted.value,
        },
      ]);

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


  function clearCollectedShares() {
    setVerifiedShares([]);
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
        <h3>Recovery context</h3>

        <div className="recovery-fields">
          <label>
            <span>Recovery request ID</span>
            <input
              value={recoveryId}
              onChange={(event) =>
                setRecoveryId(event.target.value)
              }
              placeholder="Enter recovery ID"
              required
            />
          </label>

          <label>
            <span>Protected asset ID</span>
            <input
              value={assetId}
              onChange={(event) =>
                setAssetId(event.target.value)
              }
              placeholder="Enter asset ID"
              required
            />
          </label>

          <label>
            <span>Required cryptographic threshold</span>
            <input
              type="number"
              min={2}
              max={16}
              value={threshold}
              onChange={(event) =>
                setThreshold(
                  Math.max(
                    2,
                    Math.min(16, Number(event.target.value) || 2),
                  ),
                )
              }
            />
          </label>
        </div>

        <p className="recovery-note">
          The threshold must match the protected asset's
          configured threshold. The backend currently uses
          a simple SLIP-0039 threshold scheme.
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
            disabled={loading || readyForReconstruction}
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
            {collectedCount} / {threshold}
          </strong>
        </div>

        <div className="recovery-progress">
          <div
            style={{
              width: `${Math.min(
                100,
                (collectedCount / threshold) * 100,
              )}%`,
            }}
          />
        </div>

        {verifiedShares.length === 0 ? (
          <p className="recovery-note">
            No verified shares have been collected yet.
          </p>
        ) : (
          <div className="recovery-share-list">
            {verifiedShares.map((share) => (
              <div
                className="recovery-share-item"
                key={share.trusteeId}
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
            and individually verified. Browser-side SLIP-0039
            reconstruction is the next integration step.
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
