import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Page } from "../components/Page";
import { authApiRequest } from "../lib/authApi";

interface PolicyItem {
  id: string;
  name: string;
  policy_expression: string;
  trustee_ids: string[];
  version: number;
  epoch: number;
  active: boolean;
}

interface AssetItem {
  id: string;
  name: string;
  policy_id: string;
  epoch: number;
  threshold: number;
  created_at: string;
}

interface UserItem {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
}

interface TrusteeItem {
  id: string;
  name: string;
  role: string;
  active: boolean;
}

export function Dashboard() {
  const { user } = useAuth();
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [users, setUsers] = useState<UserItem[]>([]);
  const [trustees, setTrustees] = useState<TrusteeItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    async function load() {
      setLoading(true);
      setError("");
      try {
        if (user?.role === "trustee") {
          if (active) setLoading(false);
          return;
        }
        const [policyData, assetData] = await Promise.all([
          authApiRequest<PolicyItem[]>("/api/policies"),
          authApiRequest<AssetItem[]>("/api/assets"),
        ]);
        if (!active) return;
        setPolicies(policyData);
        setAssets(assetData);
        if (user?.role === "admin") {
          const [userData, trusteeData] = await Promise.all([
            authApiRequest<UserItem[]>("/api/auth/admin/users"),
            authApiRequest<TrusteeItem[]>("/api/trustees"),
          ]);
          if (!active) return;
          setUsers(userData);
          setTrustees(trusteeData);
        }
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Unable to load dashboard data.");
      } finally {
        if (active) setLoading(false);
      }
    }
    void load();
    return () => { active = false; };
  }, [user?.role]);

  if (user?.role === "trustee") {
    return (
      <Page title="Trustee Console" sub="TRUSTEE / RESPONSIBILITY OVERVIEW">
        <section className="card">
          <small className="eyebrow">YOUR ROLE</small>
          <h3>Independent recovery authorization</h3>
          <p>You are signed in as a trustee. Your account can authorize share-release operations only for trustee records linked to your identity.</p>
          <p className="muted">The current API does not yet expose a trustee-specific assigned-recovery inbox. We will add that backend endpoint in the next recovery-workflow milestone.</p>
          <Link className="action-link" to="/recovery">Open share release workspace →</Link>
        </section>
      </Page>
    );
  }

  return (
    <Page title={user?.role === "admin" ? "System Overview" : "DeadDrop Dashboard"} sub="OVERVIEW / LIVE DATABASE STATUS">
      {error && <div className="auth-error" role="alert">{error}</div>}
      {loading ? <section className="card">Loading live protocol data…</section> : (
        <>
          <div className="grid">
            <section className="card stat-card"><small>Active Policies</small><h2>{policies.filter((item) => item.active).length}</h2></section>
            <section className="card stat-card"><small>Protected Assets</small><h2>{assets.length}</h2></section>
            <section className="card stat-card"><small>Assigned Trustee Records</small><h2>{policies.reduce((total, item) => total + item.trustee_ids.length, 0)}</h2></section>
            <section className="card stat-card"><small>Current Asset Epochs</small><h2>{assets.length ? [...new Set(assets.map((item) => item.epoch))].join(", ") : "—"}</h2></section>
          </div>
          {user?.role === "admin" && (
            <div className="grid admin-stats-grid">
              <section className="card stat-card"><small>Registered Users</small><h2>{users.length}</h2></section>
              <section className="card stat-card"><small>Trustee Records</small><h2>{trustees.length}</h2></section>
            </div>
          )}
          <section className="card">
            <div className="section-heading"><div><small className="eyebrow">PROTECTED INVENTORY</small><h3>Recent assets</h3></div><Link className="action-link" to="/policies">View policies →</Link></div>
            {assets.length === 0 ? <p className="muted">No protected assets have been registered yet.</p> : assets.slice(0, 5).map((asset) => (
              <div className="row" key={asset.id}><span><strong>{asset.name}</strong><small className="block-muted">{asset.id}</small></span><span>Epoch {asset.epoch} · {asset.threshold}-share threshold</span></div>
            ))}
          </section>
          <section className="card">
            <div className="section-heading"><div><small className="eyebrow">POLICY GOVERNANCE</small><h3>Recovery policies</h3></div></div>
            {policies.length === 0 ? <p className="muted">No policies have been created yet.</p> : policies.slice(0, 5).map((policy) => (
              <div className="row" key={policy.id}><span><strong>{policy.name}</strong><small className="block-muted">Version {policy.version} · Epoch {policy.epoch}</small></span><span className={policy.active ? "ok" : "warning-status"}>{policy.active ? "ACTIVE" : "INACTIVE"}</span></div>
            ))}
          </section>
          <section className="card protocol-disclaimer">
            <small className="eyebrow">VERIFICATION SCOPE</small>
            <h3>Structural readiness is not cryptographic proof</h3>
            <p>Dashboard counts are read from the backend database. Recovery readiness currently validates share-envelope structure and metadata; it does not yet prove successful decryption and threshold reconstruction.</p>
          </section>
        </>
      )}
    </Page>
  );
}
