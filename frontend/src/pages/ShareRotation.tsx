import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { Page } from "../components/Page";
import { authApiRequest } from "../lib/authApi";
import {
  clearRecoveredAssetKeys,
  getRecoveredAssetEntries,
  type RecoveredKeyEntry,
} from "../lib/crypto/rotationKeyVault";
import {
  rotatePolicyShares,
  type PolicyRotationResult,
} from "../lib/crypto/rotationApi";

interface PolicyItem {
  id: string;
  name: string;
  active: boolean;
  epoch: number;
  version: number;
  trustee_ids: string[];
}

interface AssetItem {
  id: string;
  policy_id: string;
  name: string;
  epoch: number;
  threshold: number;
}

export function ShareRotation() {
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [selectedPolicyId, setSelectedPolicyId] = useState("");
  const [recoveredEntries, setRecoveredEntries] = useState<RecoveredKeyEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [result, setResult] = useState<PolicyRotationResult | null>(null);

  async function loadData() {
    setError("");
    const [policyItems, assetItems] = await Promise.all([
      authApiRequest<PolicyItem[]>("/api/policies"),
      authApiRequest<AssetItem[]>("/api/assets"),
    ]);
    setPolicies(policyItems);
    setAssets(assetItems);

    const currentSelection = policyItems.find(
      (item) => item.id === selectedPolicyId,
    );
    if (!currentSelection) {
      const firstWithAssets = policyItems.find(
        (item) => item.active && assetItems.some((asset) => asset.policy_id === item.id),
      );
      setSelectedPolicyId(firstWithAssets?.id ?? "");
    }
  }

  useEffect(() => {
    let mounted = true;

    Promise.all([
      authApiRequest<PolicyItem[]>("/api/policies"),
      authApiRequest<AssetItem[]>("/api/assets"),
    ])
      .then(([policyItems, assetItems]) => {
        if (!mounted) return;
        setPolicies(policyItems);
        setAssets(assetItems);

        const firstWithAssets = policyItems.find(
          (item) => item.active && assetItems.some((asset) => asset.policy_id === item.id),
        );
        setSelectedPolicyId(firstWithAssets?.id ?? "");
      })
      .catch((err: unknown) => {
        if (mounted) {
          setError(err instanceof Error ? err.message : "Unable to load rotation data.");
        }
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    setRecoveredEntries(getRecoveredAssetEntries(selectedPolicyId));
    setResult(null);
    setSuccess("");
    setError("");
  }, [selectedPolicyId]);

  const selectedPolicy = policies.find((item) => item.id === selectedPolicyId);

  const policyAssets = useMemo(
    () => assets
      .filter((asset) => asset.policy_id === selectedPolicyId)
      .sort((a, b) => a.id.localeCompare(b.id)),
    [assets, selectedPolicyId],
  );

  const recoveredByAsset = useMemo(
    () => new Map(recoveredEntries.map((entry) => [entry.assetId, entry])),
    [recoveredEntries],
  );

  const readyAssetCount = policyAssets.filter((asset) => {
    const entry = recoveredByAsset.get(asset.id);
    return Boolean(
      entry &&
      entry.epoch === asset.epoch &&
      entry.epoch === selectedPolicy?.epoch &&
      entry.key.length === 32,
    );
  }).length;

  const allKeysReady =
    Boolean(selectedPolicy?.active) &&
    policyAssets.length > 0 &&
    readyAssetCount === policyAssets.length &&
    recoveredEntries.length === policyAssets.length &&
    policyAssets.every((asset) => {
      const entry = recoveredByAsset.get(asset.id);
      return entry?.epoch === selectedPolicy?.epoch;
    });

  function refreshRecoveredKeys() {
    setRecoveredEntries(getRecoveredAssetEntries(selectedPolicyId));
    setSuccess("");
    setError("");
  }

  async function handleRotate() {
    setError("");
    setSuccess("");
    setResult(null);

    if (!selectedPolicy) {
      setError("Select a policy first.");
      return;
    }

    if (!allKeysReady) {
      setError(
        "Recover and decrypt every protected asset under this policy in the Recovery page. The recovered keys must match the current policy epoch.",
      );
      return;
    }

    setBusy(true);
    let recoveredAssetKeys: Map<string, Uint8Array> | null = null;

    try {
      recoveredAssetKeys = new Map<string, Uint8Array>(
        recoveredEntries.map((entry) => [
          entry.assetId,
          new Uint8Array(entry.key),
        ] as const),
      );

      const rotationResult = await rotatePolicyShares({
        policyId: selectedPolicy.id,
        recoveredAssetKeys,
      });

      // Clear the original in-memory vault only after the backend has
      // verified the mined transaction and committed the new epoch.
      clearRecoveredAssetKeys(selectedPolicy.id);

      setResult(rotationResult);
      setSuccess(
        `Share rotation completed and verified. Policy epoch advanced from ${rotationResult.previous_epoch} to ${rotationResult.new_epoch}.`,
      );
      setRecoveredEntries([]);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Share rotation failed.");
    } finally {
      if (recoveredAssetKeys) {
        for (const key of recoveredAssetKeys.values()) key.fill(0);
      }
      setBusy(false);
    }
  }

  return (
    <Page
      title="Share Rotation"
      sub="KEY EPOCH MANAGEMENT / ON-CHAIN COMMITMENT UPDATE"
    >
      {error && <div className="auth-error" role="alert">{error}</div>}
      {success && <div className="admin-success" role="status">{success}</div>}

      <section className="card recovery-intro">
        <div className="recovery-heading">
          <div>
            <small>POLICY SECURITY</small>
            <h3>Re-issue trustee shares</h3>
          </div>
          <span className="recovery-indicator">CLIENT-SIDE KEY HANDLING</span>
        </div>
        <p>
          DeadDrop reconstructs each original AES key locally, generates fresh
          Shamir shares, encrypts each share for its assigned trustee, and
          updates the on-chain commitments in one atomic transaction.
        </p>
        <p className="recovery-note">
          The AES keys are held only in this browser tab. They are never uploaded
          to the backend or saved in browser storage. If you reload or close this
          tab, you must recover the assets again before rotating.
        </p>
      </section>

      <section className="card">
        <div className="section-heading">
          <div>
            <small className="eyebrow">ROTATION TARGET</small>
            <h3>Select recovery policy</h3>
          </div>
          <button type="button" className="danger" onClick={refreshRecoveredKeys} disabled={loading || busy}>
            REFRESH KEY STATUS
          </button>
        </div>

        {loading ? (
          <p>Loading policies and protected assets…</p>
        ) : (
          <>
            <label className="recovery-form">
              <span>Policy</span>
              <select
                value={selectedPolicyId}
                onChange={(event) => setSelectedPolicyId(event.target.value)}
                disabled={busy}
                style={{
                  width: "100%",
                  minHeight: 44,
                  padding: "10px 12px",
                  color: "#f2f0ed",
                  background: "#080808",
                  border: "1px solid rgba(255,255,255,.17)",
                }}
              >
                <option value="">Select a policy</option>
                {policies.map((policy) => (
                  <option key={policy.id} value={policy.id}>
                    {policy.name} · epoch {policy.epoch}
                    {!policy.active ? " · inactive" : ""}
                  </option>
                ))}
              </select>
            </label>

            {selectedPolicy && (
              <div style={{ marginTop: 22 }}>
                <div className="row">
                  <span>Current policy epoch</span>
                  <strong>{selectedPolicy.epoch}</strong>
                </div>
                <div className="row">
                  <span>Assigned trustees</span>
                  <strong>{selectedPolicy.trustee_ids.length}</strong>
                </div>
                <div className="row">
                  <span>Protected assets</span>
                  <strong>{policyAssets.length}</strong>
                </div>
                <div className="row">
                  <span>Assets with recovered current-epoch keys</span>
                  <strong>{readyAssetCount} / {policyAssets.length}</strong>
                </div>
              </div>
            )}
          </>
        )}
      </section>

      {selectedPolicy && (
        <section className="card">
          <div className="section-heading">
            <div>
              <small className="eyebrow">RECOVERY KEY CHECKLIST</small>
              <h3>Every asset must be recovered</h3>
            </div>
            <span className={allKeysReady ? "ok" : "warning-status"}>
              {allKeysReady ? "READY TO ROTATE" : "KEYS REQUIRED"}
            </span>
          </div>

          {policyAssets.length === 0 ? (
            <p>This policy has no protected assets.</p>
          ) : (
            policyAssets.map((asset) => {
              const entry = recoveredByAsset.get(asset.id);
              const valid = Boolean(
                entry &&
                entry.epoch === asset.epoch &&
                entry.epoch === selectedPolicy.epoch &&
                entry.key.length === 32,
              );

              return (
                <div className="row" key={asset.id}>
                  <div style={{ minWidth: 0 }}>
                    <strong>{asset.name || asset.id}</strong>
                    <div className="recovery-note">
                      Asset epoch {asset.epoch} · threshold {asset.threshold}
                    </div>
                  </div>
                  <span className={valid ? "ok" : "warning-status"}>
                    {valid ? "KEY RECOVERED" : entry ? "STALE KEY" : "NOT RECOVERED"}
                  </span>
                </div>
              );
            })
          )}

          <p className="recovery-note">
            To collect a missing key, open <Link to="/recovery">Emergency Recovery</Link>,
            complete an authorized recovery for that asset, and return here.
          </p>

          <div style={{ marginTop: 20, display: "flex", flexWrap: "wrap", gap: 10 }}>
            <button
              type="button"
              onClick={handleRotate}
              disabled={busy || loading || !allKeysReady}
            >
              {busy ? "ROTATION IN PROGRESS…" : "ROTATE ALL TRUSTEE SHARES"}
            </button>
            <button
              type="button"
              className="danger"
              onClick={() => {
                clearRecoveredAssetKeys(selectedPolicy.id);
                setRecoveredEntries([]);
                setSuccess("Recovered keys for this policy were cleared from browser memory.");
                setError("");
              }}
              disabled={busy || recoveredEntries.length === 0}
            >
              CLEAR RECOVERED KEYS
            </button>
          </div>
        </section>
      )}

      {result && (
        <section className="card">
          <small className="eyebrow">VERIFIED ROTATION RESULT</small>
          <h3>Policy epoch updated</h3>
          <div className="row">
            <span>Previous epoch</span>
            <strong>{result.previous_epoch}</strong>
          </div>
          <div className="row">
            <span>New epoch</span>
            <strong>{result.new_epoch}</strong>
          </div>
          <div className="row">
            <span>Assets updated</span>
            <strong>{result.updated_asset_count}</strong>
          </div>
          <div className="row">
            <span>Encrypted trustee shares stored</span>
            <strong>{result.inserted_share_count}</strong>
          </div>
          {typeof result.transaction?.hash === "string" && (
            <p className="recovery-note" style={{ overflowWrap: "anywhere" }}>
              Transaction: {result.transaction.hash}
            </p>
          )}
        </section>
      )}
    </Page>
  );
}