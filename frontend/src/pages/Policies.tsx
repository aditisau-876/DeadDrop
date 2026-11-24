import { useCallback, useEffect, useState, type FormEvent } from "react";
import { BrowserProvider, Contract } from "ethers";
import { Page } from "../components/Page";
import { authApiRequest } from "../lib/authApi";

interface PolicyItem {
  id: string;
  name: string;
  description: string | null;
  policy_expression: string;
  policy_tree: Record<string, unknown> | null;
  trustee_ids: string[];
  version: number;
  epoch: number;
  active: boolean;
  expiry_seconds: number | null;
  timelock_seconds: number | null;
}

interface TrusteeItem {
  id: string;
  name: string;
  role: string;
  wallet_address: string | null;
  active: boolean;
}

interface PolicyRegistrationPayload {
  policy_id: string;
  policy_hash: string;
  trustee_wallets: string[];
  quorum: number;
  timelock_seconds: number;
  chain_id: number;
  contract_address: string;
  contract_owner: string;
}

const registrationAbi = [
  "function registerPolicy(string policyId, bytes32 policyHash, address[] trusteeWallets, uint16 quorum, uint64 timelockDuration)",
];

export function Policies() {
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [trustees, setTrustees] = useState<TrusteeItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selectedTrustees, setSelectedTrustees] = useState<string[]>([]);
  const [threshold, setThreshold] = useState(2);
  const [timelock, setTimelock] = useState(86400);
  const [expiry, setExpiry] = useState(604800);

  const loadData = useCallback(async () => {
    const [policyItems, trusteeItems] = await Promise.all([
      authApiRequest<PolicyItem[]>("/api/policies"),
      authApiRequest<TrusteeItem[]>("/api/trustees"),
    ]);
    setPolicies(policyItems);
    setTrustees(trusteeItems);
  }, []);

  useEffect(() => {
    let mounted = true;
    Promise.all([
      authApiRequest<PolicyItem[]>("/api/policies"),
      authApiRequest<TrusteeItem[]>("/api/trustees"),
    ])
      .then(([policyItems, trusteeItems]) => {
        if (!mounted) return;
        setPolicies(policyItems);
        setTrustees(trusteeItems);
      })
      .catch((err: unknown) => {
        if (mounted) setError(err instanceof Error ? err.message : "Unable to load policy data.");
      })
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, []);

  function toggleTrustee(id: string) {
    setSelectedTrustees((current) => current.includes(id)
      ? current.filter((item) => item !== id)
      : [...current, id]);
  }

  async function createPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setSuccess("");
    if (selectedTrustees.length < 2) {
      setError("Select at least two active trustees.");
      return;
    }
    if (threshold < 2 || threshold > selectedTrustees.length) {
      setError("The approval threshold must be between 2 and the selected trustee count.");
      return;
    }
    setBusy(true);
    try {
      const children = selectedTrustees.map((trustee_id) => ({ type: "LEAF", trustee_id }));
      const expression = `${threshold}-of-${selectedTrustees.length} trustees`;
      await authApiRequest<PolicyItem>("/api/policies", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim() || null,
          policy_expression: expression,
          policy_tree: { type: "THRESHOLD", threshold, children },
          trustee_ids: selectedTrustees,
          timelock_seconds: timelock,
          expiry_seconds: expiry > 0 ? expiry : null,
        }),
      });
      setName("");
      setDescription("");
      setSelectedTrustees([]);
      setThreshold(2);
      setTimelock(86400);
      setExpiry(604800);
      await loadData();
      setSuccess("Policy created in the database. Register it on-chain using its Register button below.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy creation failed.");
    } finally {
      setBusy(false);
    }
  }

  async function registerPolicy(policy: PolicyItem) {
    setError("");
    setSuccess("");
    setBusy(true);
    try {
      if (!window.ethereum) throw new Error("MetaMask was not detected.");
      const payload = await authApiRequest<PolicyRegistrationPayload>(`/api/blockchain/registration/policies/${encodeURIComponent(policy.id)}`);
      const provider = new BrowserProvider(window.ethereum);
      const network = await provider.getNetwork();
      if (Number(network.chainId) !== payload.chain_id) {
        throw new Error(`Switch MetaMask to chain ID ${payload.chain_id} before registering.`);
      }
      const signer = await provider.getSigner();
      const signerAddress = await signer.getAddress();
      if (signerAddress.toLowerCase() !== payload.contract_owner.toLowerCase()) {
        throw new Error(`Use the contract owner wallet ${payload.contract_owner} to register policies.`);
      }
      const contract = new Contract(payload.contract_address, registrationAbi, signer);
      const tx = await contract["registerPolicy(string,bytes32,address[],uint16,uint64)"](
        payload.policy_id,
        payload.policy_hash,
        payload.trustee_wallets,
        payload.quorum,
        payload.timelock_seconds,
      );
      setSuccess(`Registration transaction submitted: ${tx.hash}. Waiting for confirmation…`);
      const receipt = await tx.wait();
      if (!receipt || receipt.status !== 1) throw new Error("The policy registration transaction failed on-chain.");
      const verified = await authApiRequest<{ verified: boolean }>(
        `/api/blockchain/registration/policies/${encodeURIComponent(policy.id)}/verify`,
        { method: "POST", body: JSON.stringify({ transaction_hash: tx.hash }) },
      );
      if (!verified.verified) throw new Error("The transaction was mined, but backend verification did not pass.");
      setSuccess(`Policy ${policy.name} is registered and verified on-chain. Transaction: ${tx.hash}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy registration failed.");
    } finally {
      setBusy(false);
    }
  }

  const activeTrustees = trustees.filter((item) => item.active);

  return (
    <Page title="Recovery Policies" sub="POLICY GOVERNANCE / ACCESS STRUCTURES">
      {error && <div className="auth-error" role="alert">{error}</div>}
      {success && <div className="admin-success" role="status">{success}</div>}

      <section className="card">
        <small className="eyebrow">POLICY CONFIGURATION</small>
        <h3>Create recovery policy</h3>
        <p className="muted">Create a flat threshold policy. Rich nested AND/OR policies remain supported by the backend but cannot yet be registered by this Solidity contract.</p>
        <form className="admin-form" onSubmit={createPolicy}>
          <label>Policy name<input required maxLength={120} value={name} onChange={(event) => setName(event.target.value)} placeholder="Personal vault recovery" /></label>
          <label>Description<textarea rows={3} value={description} onChange={(event) => setDescription(event.target.value)} /></label>
          <div>
            <label>Assign active trustees</label>
            <div className="policy-trustee-list">
              {activeTrustees.map((trustee) => (
                <label className="policy-trustee-option" key={trustee.id}>
                  <input type="checkbox" checked={selectedTrustees.includes(trustee.id)} disabled={!selectedTrustees.includes(trustee.id) && selectedTrustees.length >= 16} onChange={() => toggleTrustee(trustee.id)} />
                  <span><strong>{trustee.name}</strong><small className="block-muted">{trustee.role}{trustee.wallet_address ? ` · ${trustee.wallet_address.slice(0, 8)}…` : " · Wallet address required for on-chain registration"}</small></span>
                </label>
              ))}
              {activeTrustees.length === 0 && <p className="muted">Create active trustee records in Administration first.</p>}
            </div>
          </div>
          <label>Required approvals<input type="number" min={2} max={Math.min(16, Math.max(2, selectedTrustees.length))} value={threshold} onChange={(event) => setThreshold(Number(event.target.value))} /></label>
          <label>Recovery timelock (seconds)<input type="number" min={0} value={timelock} onChange={(event) => setTimelock(Number(event.target.value))} /></label>
          <label>Recovery expiry (seconds; 0 = no expiry)<input type="number" min={0} value={expiry} onChange={(event) => setExpiry(Number(event.target.value))} /></label>
          <button type="submit" disabled={busy || activeTrustees.length < 2}>{busy ? "PLEASE WAIT…" : "CREATE POLICY"}</button>
        </form>
      </section>

      <section>
        <div className="section-heading"><div><small className="eyebrow">POLICY REGISTRY</small><h3>Existing policies</h3></div><span>{policies.length} total</span></div>
        {loading ? <section className="card">Loading policies…</section> : policies.length === 0 ? (
          <section className="card"><h3>No recovery policies yet</h3><p className="muted">Create your first recovery policy above.</p></section>
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
            {policy.active && <button type="button" disabled={busy} onClick={() => void registerPolicy(policy)}>REGISTER POLICY ON-CHAIN</button>}
          </section>
        ))}
      </section>
    </Page>
  );
}
