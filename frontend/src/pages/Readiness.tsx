import { Page } from "./Dashboard";

const trustees = [
  "Security Lead",
  "CTO",
  "External Auditor",
  "Admin 1",
  "Admin 2",
];

export function Readiness() {
  return (
    <Page
      title="Share Readiness Monitor"
      sub="Public commitment metadata; raw shares stay off-chain."
    >
      <section className="card">
        <h3>Epoch 4 · 5 / 5 verified</h3>

        {trustees.map((trustee) => (
          <div className="row" key={trustee}>
            <span>{trustee}</span>
            <span className="ok">Verified</span>
          </div>
        ))}
      </section>
    </Page>
  );
}