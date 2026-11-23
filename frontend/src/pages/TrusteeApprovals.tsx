
import { useCallback, useEffect, useState } from "react";
import { Page } from "../components/Page";
import { authApiRequest } from "../lib/authApi";
import { signRecoveryApproval } from "../lib/crypto/recoveryApproval";

interface TrusteeProfile {
  id: string;
  name: string;
  role: string;
  wallet_address: string | null;
  public_key: string | null;
  active: boolean;
}

interface RecoveryItem {
  id: string;
  policy_id: string;
  reason: string;
  incident_hash: string;
  status: string;
  approvals: number;
  required_approvals: number;
  policy_version: number;
  policy_epoch: number;
  expires_at: string | null;
  execute_after: string | null;
  can_release: boolean;
}

export function TrusteeApprovals() {
  const [trustee, setTrustee] =
    useState<TrusteeProfile | null>(null);

  const [recoveries, setRecoveries] =
    useState<RecoveryItem[]>([]);

  const [loading, setLoading] = useState(true);
  const [approvingId, setApprovingId] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const loadInbox = useCallback(async () => {
    setError("");

    try {
      const [profile, items] = await Promise.all([
        authApiRequest<TrusteeProfile>(
          "/api/trustees/me",
        ),
        authApiRequest<RecoveryItem[]>(
          "/api/recovery",
        ),
      ]);

      setTrustee(profile);
      setRecoveries(items);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load trustee inbox.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadInbox();
  }, [loadInbox]);

  async function handleApprove(
    recovery: RecoveryItem,
  ) {
    if (!trustee) {
      setError("Trustee profile is unavailable.");
      return;
    }

    if (!trustee.wallet_address) {
      setError(
        "Your trustee profile does not have a registered wallet.",
      );
      return;
    }

    if (recovery.status !== "PENDING") {
      setError(
        "Only pending recovery requests can be approved.",
      );
      return;
    }

    setApprovingId(recovery.id);
    setError("");
    setSuccess("");

    try {
      // Step 1: Construct the exact EIP-712 approval payload.
      const signature = await signRecoveryApproval(
        {
          recoveryId: recovery.id,
          policyId: recovery.policy_id,
          trusteeId: trustee.id,
          incidentHash: recovery.incident_hash,
          policyVersion: recovery.policy_version,
          policyEpoch: recovery.policy_epoch,
        },
        trustee.wallet_address,
      );

      // Step 2: Submit the signature to the existing API.
      const updated = await authApiRequest<RecoveryItem>(
        `/api/recovery/${encodeURIComponent(recovery.id)}/approve`,
        {
          method: "POST",
          body: JSON.stringify({
            recovery_id: recovery.id,
            trustee_id: trustee.id,
            signature,
          }),
        },
      );

      // Step 3: Update the displayed recovery status.
      setRecoveries((current) =>
        current.map((item) =>
          item.id === updated.id ? updated : item,
        ),
      );

      setSuccess(
        `Approval submitted successfully. Current approvals: ${updated.approvals} / ${updated.required_approvals}.`,
      );

      // Refresh from the backend to get the latest state.
      await loadInbox();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Approval could not be submitted.",
      );
    } finally {
      setApprovingId("");
    }
  }

  const pendingRecoveries = recoveries.filter(
    (item) => item.status === "PENDING",
  );

  const otherRecoveries = recoveries.filter(
    (item) => item.status !== "PENDING",
  );

  return (
    <Page
      title="Trustee Approval Inbox"
      sub="REVIEW RECOVERY REQUESTS / VERIFY AND AUTHORIZE"
    >
      <section className="card recovery-intro">
        <div className="recovery-heading">
          <div>
            <small>TRUSTEE CONSOLE</small>
            <h3>
              {trustee
                ? `Welcome, ${trustee.name}`
                : "Your assigned recovery requests"}
            </h3>
          </div>

          <span className="recovery-indicator">
            EIP-712 AUTHORIZATION
          </span>
        </div>

        <p>
          Review recovery requests assigned to you.
          Approving a request requires signing a structured
          message using your registered MetaMask wallet.
        </p>

        {trustee && (
          <div className="trustee-wallet">
            <small>REGISTERED TRUSTEE WALLET</small>
            <strong>
              {trustee.wallet_address || "No wallet registered"}
            </strong>
          </div>
        )}
      </section>

      {error && (
        <div className="recovery-alert recovery-error" role="alert">
          {error}
        </div>
      )}

      {success && (
        <div className="recovery-alert recovery-success" role="status">
          {success}
        </div>
      )}

      {loading ? (
        <section className="card">
          Loading your recovery inbox…
        </section>
      ) : (
        <>
          <section className="card">
            <div className="section-heading">
              <div>
                <small className="eyebrow">
                  ACTION REQUIRED
                </small>
                <h3>Pending approvals</h3>
              </div>

              <strong className="recovery-count">
                {pendingRecoveries.length}
              </strong>
            </div>

            {pendingRecoveries.length === 0 ? (
              <p className="muted">
                No pending recovery requests are assigned to
                your trustee profile.
              </p>
            ) : (
              <div className="trustee-request-list">
                {pendingRecoveries.map((recovery) => {
                  const progress = Math.min(
                    100,
                    (recovery.approvals /
                      Math.max(1, recovery.required_approvals)) *
                      100,
                  );

                  return (
                    <article
                      className="trustee-request"
                      key={recovery.id}
                    >
                      <div className="section-heading">
                        <div>
                          <small className="eyebrow">
                            RECOVERY REQUEST
                          </small>
                          <h3>
                            {recovery.id.slice(0, 16)}
                          </h3>
                        </div>

                        <span className="warning-status">
                          PENDING
                        </span>
                      </div>

                      <p>{recovery.reason}</p>

                      <div className="row">
                        <span>Policy ID</span>
                        <strong>{recovery.policy_id}</strong>
                      </div>

                      <div className="row">
                        <span>Policy version</span>
                        <strong>
                          {recovery.policy_version}
                        </strong>
                      </div>

                      <div className="row">
                        <span>Policy epoch</span>
                        <strong>
                          {recovery.policy_epoch}
                        </strong>
                      </div>

                      <div className="row">
                        <span>Approval progress</span>
                        <strong>
                          {recovery.approvals} /{" "}
                          {recovery.required_approvals}
                        </strong>
                      </div>

                      <div className="recovery-progress">
                        <div
                          style={{ width: `${progress}%` }}
                        />
                      </div>

                      <div className="trustee-incident">
                        <small>INCIDENT HASH</small>
                        <code>{recovery.incident_hash}</code>
                      </div>

                      <div className="trustee-incident">
                        <small>EXPIRY</small>
                        <span>
                          {recovery.expires_at
                            ? new Date(
                                recovery.expires_at,
                              ).toLocaleString()
                            : "No expiry configured"}
                        </span>
                      </div>

                      <button
                        type="button"
                        onClick={() =>
                          void handleApprove(recovery)
                        }
                        disabled={
                          approvingId !== "" ||
                          !trustee?.wallet_address
                        }
                      >
                        {approvingId === recovery.id
                          ? "Waiting for signature..."
                          : "Review and sign approval"}
                      </button>
                    </article>
                  );
                })}
              </div>
            )}
          </section>

          <section className="card">
            <div className="section-heading">
              <div>
                <small className="eyebrow">
                  REQUEST HISTORY
                </small>
                <h3>Other recovery requests</h3>
              </div>
            </div>

            {otherRecoveries.length === 0 ? (
              <p className="muted">
                No other recovery requests to display.
              </p>
            ) : (
              otherRecoveries.map((recovery) => (
                <div className="row" key={recovery.id}>
                  <span>
                    {recovery.id.slice(0, 16)}
                  </span>
                  <strong>{recovery.status}</strong>
                </div>
              ))
            )}
          </section>
        </>
      )}
    </Page>
  );
}
