import type { ReactNode } from "react";

const stats = [
  ["Active Policies", "4"],
  ["Trustees Verified", "5 / 5"],
  ["Pending Recoveries", "1"],
  ["Current Epoch", "4"],
];

export function Dashboard() {
  return (
    <Page
      title="DeadDrop Dashboard"
      sub="Publicly verifiable emergency recovery status."
    >
      <div className="grid">
        {stats.map(([label, value]) => (
          <section className="card" key={label}>
            <small>{label}</small>
            <h2>{value}</h2>
          </section>
        ))}
      </div>

      <section className="card">
        <h3>Master Root Signing Key</h3>

        <div className="tree">
          (Security Lead AND CTO) OR
          <br />
          (External Auditor AND Threshold(2, Admins))
        </div>

        <p>
          Governance quorum and cryptographic readiness are tracked
          independently.
        </p>
      </section>
    </Page>
  );
}

type PageProps = {
  title: string;
  sub: string;
  children?: ReactNode;
};

export function Page({ title, sub, children }: PageProps) {
  return (
    <div className="page">
      <small>{sub}</small>
      <h1>{title}</h1>
      {children}
    </div>
  );
}