import { useEffect, useState, type FormEvent } from "react";
import { BrowserProvider, Contract } from "ethers";
import { Page } from "../components/Page";
import { authApiRequest } from "../lib/authApi";
import { createProtectedAssetBundle } from "../lib/crypto/recovery";

interface AssetItem {
  id: string;
  policy_id: string;
  name: string;
  description: string | null;
  epoch: number;
  threshold: number;
  created_at: string;
}
interface PolicyItem {
  id: string;
  name: string;
  active: boolean;
  epoch: number;
  trustee_ids: string[];
  policy_tree: { type?: string; children?: Array<{ type?: string }> } | null;
}
interface TrusteeItem {
  id: string;
  name: string;
  role: string;
  wallet_address: string | null;
  public_key: string | null;
  active: boolean;
}
interface AssetRegistrationPayload {
  asset_id: string;
  policy_id: string;
  asset_hash: string;
  epoch: number;
  trustee_wallets: string[];
  share_commitments: string[];
  chain_id: number;
  contract_address: string;
  contract_owner: string;
}

const assetAbi = [
  "function registerAssetCommitments(string assetId,string policyId,bytes32 assetHash,uint64 epoch,address[] trusteeWallets,bytes32[] shareCommitments)",
];

export function Assets() {
  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [trustees, setTrustees] = useState<TrusteeItem[]>([]);
  const [selectedPolicyId, setSelectedPolicyId] = useState("");
  const [assetName, setAssetName] = useState("");
  const [description, setDescription] = useState("");
  const [plaintext, setPlaintext] = useState("");
  const [threshold, setThreshold] = useState(2);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [busyId, setBusyId] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  async function loadData() {
    const [assetItems, policyItems, trusteeItems] = await Promise.all([
      authApiRequest<AssetItem[]>("/api/assets"),
      authApiRequest<PolicyItem[]>("/api/policies"),
      authApiRequest<TrusteeItem[]>("/api/trustees"),
    ]);
    setAssets(assetItems);
    setPolicies(policyItems);
    setTrustees(trusteeItems);
    if (!selectedPolicyId) {
      const first = policyItems.find((item) => item.active && item.policy_tree?.type === "THRESHOLD" && item.policy_tree.children?.every((child) => child.type === "LEAF"));
      if (first) setSelectedPolicyId(first.id);
    }
  }

  useEffect(() => {
    let mounted = true;
    Promise.all([
      authApiRequest<AssetItem[]>("/api/assets"),
      authApiRequest<PolicyItem[]>("/api/policies"),
      authApiRequest<TrusteeItem[]>("/api/trustees"),
    ])
      .then(([assetItems, policyItems, trusteeItems]) => {
        if (!mounted) return;
        setAssets(assetItems);
        setPolicies(policyItems);
        setTrustees(trusteeItems);
        const first = policyItems.find((item) => item.active && item.policy_tree?.type === "THRESHOLD" && item.policy_tree.children?.every((child) => child.type === "LEAF"));
        if (first) setSelectedPolicyId(first.id);
      })
      .catch((err: unknown) => {
        if (mounted) setError(err instanceof Error ? err.message : "Unable to load protected asset data.");
      })
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, []);

  const selectedPolicy = policies.find((item) => item.id === selectedPolicyId);
  const assignedTrustees = (selectedPolicy?.trustee_ids ?? [])
    .map((id) => trustees.find((trustee) => trustee.id === id))
    .filter((trustee): trustee is TrusteeItem => Boolean(trustee && trustee.active));

  async function createAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setSuccess("");
    if (!selectedPolicy) {
      setError("Select an active policy first.");
      return;
    }
    if (assignedTrustees.length !== selectedPolicy.trustee_ids.length) {
      setError("Every trustee assigned to this policy must still be active.");
      return;
    }
    if (assignedTrustees.some((trustee) => !trustee.public_key)) {
      setError("Every assigned trustee needs an X25519 public encryption key. Configure these in Administration before protecting an asset.");
      return;
    }
    if (threshold < 2 || threshold > assignedTrustees.length) {
      setError("The cryptographic threshold must be between 2 and the assigned trustee count.");
      return;
    }
    setBusy(true);
    try {
      // AES encryption, Shamir splitting, X25519 share encryption and
      // commitments all happen in this browser. Plaintext is not posted.
      const bundle = await createProtectedAssetBundle({
        plaintext,
        policyId: selectedPolicy.id,
        epoch: selectedPolicy.epoch,
        threshold,
        trustees: assignedTrustees.map((trustee) => ({
          id: trustee.id,
          name: trustee.name,
          public_key: trustee.public_key,
        })),
      });
      const created = await authApiRequest<AssetItem>("/api/assets/protect", {
        method: "POST",
        body: JSON.stringify({
          policy_id: selectedPolicy.id,
          name: assetName.trim(),
          description: description.trim() || null,
          ...bundle,
        }),
      });
      setAssetName("");
      setDescription("");
      setPlaintext("");
      setSuccess(`Asset "${created.name}" encrypted and stored. Its individual trustee commitments can now be registered on-chain.`);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Asset protection failed.");
    } finally {
      setBusy(false);
    }
  }

  async function registerAsset(asset: AssetItem) {
    setError("");
    setSuccess("");
    setBusyId(asset.id);
    try {
      if (!window.ethereum) throw new Error("MetaMask was not detected.");
      const payload = await authApiRequest<AssetRegistrationPayload>(`/api/blockchain/registration/assets/${encodeURIComponent(asset.id)}`);
      const provider = new BrowserProvider(window.ethereum);
      const network = await provider.getNetwork();
      if (Number(network.chainId) !== payload.chain_id) throw new Error(`Switch MetaMask to chain ID ${payload.chain_id}.`);
      const signer = await provider.getSigner();
      const signerAddress = await signer.getAddress();
      if (signerAddress.toLowerCase() !== payload.contract_owner.toLowerCase()) {
        throw new Error(`Use the contract owner wallet ${payload.contract_owner} to register asset commitments.`);
      }
      const contract = new Contract(payload.contract_address, assetAbi, signer);
      const tx = await contract.registerAssetCommitments(
        payload.asset_id,
        payload.policy_id,
        payload.asset_hash,
        payload.epoch,
        payload.trustee_wallets,
        payload.share_commitments,
      );
      setSuccess(`Asset commitment transaction submitted: ${tx.hash}. Waiting for confirmation…`);
      const receipt = await tx.wait();
      if (!receipt || receipt.status !== 1) throw new Error("The asset commitment transaction failed.");
      const result = await authApiRequest<{ verified: boolean }>(
        `/api/blockchain/registration/assets/${encodeURIComponent(asset.id)}/verify`,
        { method: "POST", body: JSON.stringify({ transaction_hash: tx.hash }) },
      );
      if (!result.verified) throw new Error("The transaction was mined but commitment verification did not pass.");
      setSuccess(`Asset ${asset.name}: per-trustee commitments registered and verified on-chain. Transaction: ${tx.hash}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to register asset commitments.");
    } finally {
      setBusyId("");
    }
  }

  return (
    <Page title="Protected Assets" sub="CLIENT-SIDE ENCRYPTION / ASSET-SCOPED SHARE COMMITMENTS">
      {error && <div className="auth-error" role="alert">{error}</div>}
      {success && <div className="admin-success" role="status">{success}</div>}

      <section className="card">
        <small className="eyebrow">OWNER WORKFLOW</small>
        <h3>Protect a new asset</h3>
        <p className="muted">The content is encrypted in your browser with AES-256-GCM. Its key is split into threshold shares and each share is encrypted for its assigned trustee using X25519. Only ciphertext and encrypted shares are sent to the backend. Choose a flat threshold policy that has been registered on-chain before anchoring the asset commitments.</p>
        <form className="admin-form" onSubmit={createAsset}>
          <label>Recovery policy
            <select required value={selectedPolicyId} onChange={(event) => setSelectedPolicyId(event.target.value)}>
              {policies.filter((policy) => policy.active && policy.policy_tree?.type === "THRESHOLD" && policy.policy_tree.children?.every((child) => child.type === "LEAF")).map((policy) => <option key={policy.id} value={policy.id}>{policy.name}</option>)}
            </select>
          </label>
          <div className="row"><span>Active trustees assigned</span><strong>{assignedTrustees.length}</strong></div>
          <label>Asset name<input required maxLength={120} value={assetName} onChange={(event) => setAssetName(event.target.value)} placeholder="e.g. Recovery document" /></label>
          <label>Description<textarea rows={2} value={description} onChange={(event) => setDescription(event.target.value)} /></label>
          <label>Secret / content to protect<textarea required rows={5} value={plaintext} onChange={(event) => setPlaintext(event.target.value)} placeholder="Enter the content. It will be encrypted locally before upload." /></label>
          <label>Required shares to reconstruct (threshold)
            <input type="number" min={2} max={Math.min(16, Math.max(2, assignedTrustees.length))} value={threshold} onChange={(event) => setThreshold(Number(event.target.value))} />
          </label>
          <small className="block-muted">Each assigned trustee receives one encrypted share. At least the selected threshold is required to reconstruct the AES key.</small>
          <button type="submit" disabled={busy || !selectedPolicy || assignedTrustees.length < 2}>{busy ? "ENCRYPTING & PROTECTING…" : "ENCRYPT & PROTECT ASSET"}</button>
        </form>
      </section>

      <section>
        <div className="section-heading"><div><small className="eyebrow">ASSET REGISTRY</small><h3>Protected assets</h3></div><span>{assets.length} total</span></div>
        {loading ? <section className="card">Loading protected assets…</section> : assets.length === 0 ? (
          <section className="card"><p className="muted">No protected assets yet. Create one using the form above.</p></section>
        ) : assets.map((asset) => (
          <section className="card policy-card" key={asset.id}>
            <div className="section-heading"><div><small className="eyebrow">PROTECTED ASSET · EPOCH {asset.epoch}</small><h3>{asset.name}</h3></div><span className="ok">ENCRYPTED</span></div>
            {asset.description && <p>{asset.description}</p>}
            <div className="row"><span>Policy ID</span><strong>{asset.policy_id}</strong></div>
            <div className="row"><span>Reconstruction threshold</span><strong>{asset.threshold}</strong></div>
            <small className="block-muted">Asset ID: {asset.id}</small>
            <div className="asset-workflow-actions"><button type="button" disabled={Boolean(busyId)} onClick={() => void registerAsset(asset)}>{busyId === asset.id ? "REGISTERING…" : "REGISTER SHARE COMMITMENTS ON-CHAIN"}</button></div>
          </section>
        ))}
      </section>
    </Page>
  );
}
