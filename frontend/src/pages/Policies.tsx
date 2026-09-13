import { Page } from "./Dashboard";

export function Policies() {
  return (
    <Page
      title="Recovery Policies"
      sub="Composable monotonic access structures."
    >
      <section className="card">
        <h3>Policy v2 · Epoch 4</h3>

        <div className="tree">
          (Security Lead AND CTO) OR
          <br />
          (Auditor AND Threshold(2, Admins))
        </div>

        <p>
          Trustees: CTO, Security Lead, External Auditor, Admin 1, Admin 2.
        </p>
      </section>
    </Page>
  );
}