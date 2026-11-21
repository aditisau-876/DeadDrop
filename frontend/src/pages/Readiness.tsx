import { useEffect, useState } from "react";
import { Page } from "../components/Page";
import { authApiRequest } from "../lib/authApi";

interface AssetItem {
  id: string;
  name: string;
  epoch: number;
  threshold: number;
}

interface ReadinessResult {
  asset_id: string;
  ready_for_recovery: boolean;
  reason: string;
  threshold: number;
  valid_structural_shares: number;
  assigned_trustees: number;
  missing_trustees: string[];
  invalid_shares: { trustee_id: string; reason: string }[];
  commitments_present: boolean;
  cryptographic_proof_verified: boolean;
  policy_epoch?: number;
  asset_epoch?: number;
}

export function Readiness() {
  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [result, setResult] = useState<ReadinessResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    authApiRequest<AssetItem[]>("/api/assets")
      .then((items) => {
        if (!active) return;
        setAssets(items);
        if (items.length) setSelectedId(items[0].id);
      })
      .catch((err: unknown) => { if (active) setError(err instanceof Error ? err.message : "Unable to load assets."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!selectedId) { setResult(null); return; }
    let active = true;
    setChecking(true);
    setError("");
    authApiRequest<ReadinessResult>(`/api/assets/${encodeURIComponent(selectedId)}/readiness`)
      .then((data) => { if (active) setResult(data); })
      .catch((err: unknown) => { if (active) setError(err instanceof Error ? err.message : "Readiness check failed."); })
      .finally(() => { if (active) setChecking(false); });
    return () => { active = false; };
  }, [selectedId]);

  return (
    <Page title="Share Readiness Monitor" sub="LIVE STRUCTURAL VALIDATION / CRYPTOGRAPHIC STATUS">
      {error && <div className="auth-error" role="alert">{error}</div>}
      <section className="card">
        <div className="section-heading"><div><small className="eyebrow">PROTECTED ASSET</small><h3>Choose an asset to inspect</h3></div></div>
        {loading ? <p>Loading assets…</p> : assets.length === 0 ? <p className="muted">No protected assets are registered for this account.</p> : (
          <select className="readiness-select" value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>
            {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.name} · {asset.id}</option>)}
          </select>
        )}
      </section>
      {checking && <section className="card">Checking encrypted share metadata…</section>}
      {result && !checking && (
        <>
          <section className="card">
            <div className="section-heading"><div><small className="eyebrow">STRUCTURAL READINESS</small><h3>{result.ready_for_recovery ? "Threshold packages available" : "Recovery not structurally ready"}</h3></div><span className={result.ready_for_recovery ? "ok" : "warning-status"}>{result.ready_for_recovery ? "STRUCTURALLY READY" : "NOT READY"}</span></div>
            <p>{result.reason}</p>
            <div className="grid">
              <div className="stat-card"><small>Valid structural shares</small><h2>{result.valid_structural_shares} / {result.assigned_trustees}</h2></div>
              <div className="stat-card"><small>Required threshold</small><h2>{result.threshold}</h2></div>
            </div>
            <div className="row"><span>Commitment metadata present</span><strong>{result.commitments_present ? "Yes" : "No"}</strong></div>
            <div className="row"><span>Cryptographic proof verified</span><strong className="warning-status">{result.cryptographic_proof_verified ? "Yes" : "No"}</strong></div>
          </section>
          {result.missing_trustees.length > 0 && <section className="card"><h3>Missing trustee shares</h3>{result.missing_trustees.map((id) => <div className="row" key={id}>{id}</div>)}</section>}
          {result.invalid_shares.length > 0 && <section className="card"><h3>Invalid share packages</h3>{result.invalid_shares.map((item) => <div className="row" key={item.trustee_id}><span>{item.trustee_id}</span><span className="warning-status">{item.reason}</span></div>)}</section>}
          <section className="card protocol-disclaimer"><h3>Important security distinction</h3><p>This endpoint validates structural metadata and encrypted envelope format. It does not decrypt shares, reconstruct the secret, or prove that the reconstructed secret matches the original. Do not interpret “structurally ready” as proof of successful recovery.</p></section>
        </>
      )}
    </Page>
  );
}
