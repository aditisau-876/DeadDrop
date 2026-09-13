import { useState } from "react";
import { Page } from "./Dashboard";

export function Recovery() {
  const [cancelled, setCancelled] = useState(false);
  const [started, setStarted] = useState(false);

  return (
    <Page
      title="Emergency Recovery"
      sub="Governance quorum + cryptographic quorum."
    >
      <section className="card">
        <h3>Ransomware / IdP lockout</h3>

        <p>
          Request → approvals → timelock → encrypted share release →
          client verification → local reconstruction.
        </p>

        <div>
          <button
            disabled={cancelled || started}
            onClick={() => setStarted(true)}
          >
            {started ? "Recovery started" : "Start simulated recovery"}
          </button>

          <button
            className="danger"
            disabled={cancelled}
            onClick={() => setCancelled(true)}
          >
            Cancel
          </button>
        </div>

        {started && !cancelled && (
          <p className="ok">Recovery simulation initiated.</p>
        )}

        {cancelled && (
          <p className="danger-text">Recovery request cancelled.</p>
        )}
      </section>
    </Page>
  );
}