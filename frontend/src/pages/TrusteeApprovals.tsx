
import { useCallback, useEffect, useState } from "react";
import { BrowserProvider, Contract, keccak256, toUtf8Bytes } from "ethers";
import { Page } from "../components/Page";
import { authApiRequest } from "../lib/authApi";
import { signRecoveryApproval } from "../lib/crypto/recoveryApproval";

const approvalContractAbi = [
  "function submitApproval(string recoveryId,string policyId,string trusteeId,string incidentHash,bytes signature)",
  "function approved(bytes32 recoveryKey,address trustee) view returns (bool)",
];

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

    if (!(["PENDING", "APPROVED"] as string[]).includes(recovery.status)) {
      setError("This recovery request is no longer eligible for approval relay.");
      return;
    }

    setApprovingId(recovery.id);
    setError("");
    setSuccess("");

    try {
      // Step 1: Reuse a previously stored signature when the backend
      // approval succeeded but its blockchain relay did not.
      let signature: string;
      let updated: RecoveryItem;
      if (recovery.status === "APPROVED") {
        const stored = await authApiRequest<{ signature: string }>(
          `/api/blockchain/registration/recoveries/${encodeURIComponent(recovery.id)}/approvals/${encodeURIComponent(trustee.id)}`,
        );
        signature = stored.signature;
        updated = recovery;
      } else {
        signature = await signRecoveryApproval(
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

        try {
          updated = await authApiRequest<RecoveryItem>(
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
        } catch (approvalError) {
          const message = approvalError instanceof Error ? approvalError.message : "";
          if (!message.toLowerCase().includes("already approved")) throw approvalError;
          const stored = await authApiRequest<{ signature: string }>(
            `/api/blockchain/registration/recoveries/${encodeURIComponent(recovery.id)}/approvals/${encodeURIComponent(trustee.id)}`,
          );
          signature = stored.signature;
          updated = await authApiRequest<RecoveryItem>(
            `/api/recovery/${encodeURIComponent(recovery.id)}`,
          );
        }
      }

      setRecoveries((current) => current.map((item) => item.id === updated.id ? updated : item));

      // Step 3: Relay the exact backend-verified signature to Solidity.
      try {
        if (!window.ethereum) throw new Error("MetaMask was not detected.");
        const status = await authApiRequest<{
          configured_chain_id: number;
          contract_address: string | null;
        }>("/api/blockchain/status");
        if (!status.contract_address) throw new Error("DeadDrop contract address is not configured on the backend.");
        const provider = new BrowserProvider(window.ethereum);
        const network = await provider.getNetwork();
        if (Number(network.chainId) !== status.configured_chain_id) {
          throw new Error(`Switch MetaMask to chain ID ${status.configured_chain_id}.`);
        }
        const signer = await provider.getSigner();
        const contract = new Contract(status.contract_address, approvalContractAbi, signer);
        const recoveryKey = keccak256(toUtf8Bytes(recovery.id));
        const alreadyRelayed = await contract.approved(recoveryKey, trustee.wallet_address);
        let transactionHash = "already recorded on-chain";
        if (!alreadyRelayed) {
          const tx = await contract.submitApproval(
            recovery.id,
            recovery.policy_id,
            trustee.id,
            recovery.incident_hash,
            signature,
          );
          const receipt = await tx.wait();
          if (!receipt || receipt.status !== 1) throw new Error("The approval relay transaction failed.");
          transactionHash = tx.hash;
        }
        const chainRecovery = await authApiRequest<{ blockchain: { approvals: number } }>(
          `/api/blockchain/contract/recoveries/${encodeURIComponent(recovery.id)}`,
        );
        setSuccess(`Approval verified by the backend and recorded on-chain. On-chain approvals: ${chainRecovery.blockchain.approvals}. Transaction: ${transactionHash}`);
      } catch (relayError) {
        const relayMessage = relayError instanceof Error ? relayError.message : "Unknown blockchain relay error.";
        setError(`Your trustee approval is saved and verified by the backend, but on-chain relay did not complete: ${relayMessage} You can click Approve again to retry the relay.`);
      }

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
                    <small className="block-muted">{recovery.status}</small>
                  </span>
                  {recovery.status === "APPROVED" && (
                    <button
                      type="button"
                      disabled={approvingId !== "" || !trustee?.wallet_address}
                      onClick={() => void handleApprove(recovery)}
                    >
                      {approvingId === recovery.id ? "RELAYING…" : "RETRY ON-CHAIN RELAY"}
                    </button>
                  )}
                </div>
              ))
            )}
          </section>
        </>
      )}
    </Page>
  );
}
