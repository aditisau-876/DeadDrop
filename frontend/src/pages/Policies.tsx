import { useEffect, useState } from "react";
import { Page } from "../components/Page";
import { authApiRequest } from "../lib/authApi";

interface PolicyItem {
  id: string;
  name: string;
  description: string | null;
  policy_expression: string;
  trustee_ids: string[];
  version: number;
  epoch: number;
  active: boolean;
  expiry_seconds: number | null;
  timelock_seconds: number | null;
}

export function Policies() {
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    authApiRequest<PolicyItem[]>("/api/policies")
      .then((items) => { if (active) setPolicies(items); })
      .catch((err: unknown) => { if (active) setError(err instanceof Error ? err.message : "Unable to load policies."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  return (
    <Page title="Recovery Policies" sub="POLICY GOVERNANCE / ACCESS STRUCTURES">
      {error && <div className="auth-error" role="alert">{error}</div>}
      {loading ? <section className="card">Loading policies…</section> : policies.length === 0 ? (
        <section className="card"><h3>No recovery policies yet</h3><p className="muted">Policies created through the backend will appear here. Policy creation UI is the next owner-workflow addition.</p></section>
      ) : policies.map((policy) => (
        <section className="card policy-card" key={policy.id}>
          <div className="section-heading">
            <div><small className="eyebrow">POLICY · VERSION {policy.version}</small><h3>{policy.name}</h3></div>
            <span className={policy.active ? "ok" : "warning-status"}>{policy.active ? "ACTIVE" : "INACTIVE"}</span>
          </div>
          {policy.description && <p>{policy.description}</p>}
          <div className="tree">{policy.policy_expression}</div>
          <div className="row"><span>Trustees assigned</span><strong>{policy.trustee_ids.length}</strong></div>
          <div className="row"><span>Current epoch</span><strong>{policy.epoch}</strong></div>
          <div className="row"><span>Timelock</span><strong>{policy.timelock_seconds == null ? "Not configured" : `${policy.timelock_seconds} seconds`}</strong></div>
          <div className="row"><span>Expiry</span><strong>{policy.expiry_seconds == null ? "Not configured" : `${policy.expiry_seconds} seconds`}</strong></div>
          <small className="block-muted">Policy ID: {policy.id}</small>
        </section>
      ))}
    </Page>
  );
}
