
import { Page } from "../components/Page";

const stats = [
  {
    label: "Active Policies",
    value: "4",
  },
  {
    label: "Trustees Verified",
    value: "5 / 5",
  },
  {
    label: "Pending Recoveries",
    value: "1",
  },
  {
    label: "Current Epoch",
    value: "4",
  },
];

export function Dashboard() {
  return (
    <Page
      title="DeadDrop Dashboard"
      sub="OVERVIEW / SECURITY STATUS"
    >
      <div className="grid">
        {stats.map((stat) => (
          <section className="card stat-card" key={stat.label}>
            <small>{stat.label}</small>
            <h2>{stat.value}</h2>
          </section>
        ))}
      </div>

      <section className="card policy-overview">
        <div className="section-heading">
          <div>
            <small className="eyebrow">ACCESS STRUCTURE</small>
            <h3>Master Root Signing Key</h3>
          </div>

          <span className="ok">Policy Active</span>
        </div>

        <div className="tree">
          <div>(Security Lead AND CTO)</div>
          <div className="tree-operator">OR</div>
          <div>
            (External Auditor AND Threshold(2, Admins))
          </div>
        </div>

        <p>
          Governance quorum and cryptographic readiness are
          tracked independently.
        </p>
      </section>

      <section className="card">
        <div className="section-heading">
          <div>
            <small className="eyebrow">PROTOCOL STATUS</small>
            <h3>Recovery Infrastructure</h3>
          </div>
        </div>

        <div className="row">
          <span>Policy evaluation</span>
          <span className="ok">Available</span>
        </div>

        <div className="row">
          <span>Encrypted share storage</span>
          <span className="ok">Available</span>
        </div>

        <div className="row">
          <span>Trustee share release</span>
          <span className="ok">API configured</span>
        </div>

        <div className="row">
          <span>On-chain enforcement</span>
          <span className="warning-status">Not deployed</span>
        </div>
      </section>
    </Page>
  );
}
