import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Page } from "../components/Page";
import { useAuth } from "../auth/AuthContext";
import { authApiRequest } from "../lib/authApi";

interface UserItem {
  id: string;
  email: string;
  full_name: string;
  role: "owner" | "trustee" | "admin";
  is_active: boolean;
}

interface TrusteeItem {
  id: string;
  name: string;
  role: string;
  wallet_address: string | null;
  public_key: string | null;
  active: boolean;
}

export function Admin() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<UserItem[]>([]);
  const [trustees, setTrustees] = useState<TrusteeItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [trusteeName, setTrusteeName] = useState("");
  const [trusteeRole, setTrusteeRole] = useState("Trusted contact");
  const [walletAddress, setWalletAddress] = useState("");
  const [publicKey, setPublicKey] = useState("");

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [accountRole, setAccountRole] = useState<"owner" | "trustee" | "admin">("owner");
  const [trusteeId, setTrusteeId] = useState("");

  const loadData = useCallback(async () => {
    const [userData, trusteeData] = await Promise.all([
      authApiRequest<UserItem[]>("/api/auth/admin/users"),
      authApiRequest<TrusteeItem[]>("/api/trustees"),
    ]);
    setUsers(userData);
    setTrustees(trusteeData);
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([
      authApiRequest<UserItem[]>("/api/auth/admin/users"),
      authApiRequest<TrusteeItem[]>("/api/trustees"),
    ])
      .then(([userData, trusteeData]) => {
        if (!active) return;
        setUsers(userData);
        setTrustees(trusteeData);
      })
      .catch((err: unknown) => { if (active) setError(err instanceof Error ? err.message : "Unable to load administration data."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  async function createTrustee(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setSuccess("");
    try {
      const created = await authApiRequest<TrusteeItem>("/api/trustees", {
        method: "POST",
        body: JSON.stringify({
          name: trusteeName.trim(),
          role: trusteeRole.trim(),
          wallet_address: walletAddress.trim() || null,
          public_key: publicKey.trim() || null,
        }),
      });
      await loadData();
      setTrusteeId(created.id);
      setTrusteeName(""); setWalletAddress(""); setPublicKey("");
      setSuccess(`Trustee record created. ID: ${created.id}. You can now create and link its login account below.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Trustee creation failed.");
    } finally { setBusy(false); }
  }

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setSuccess("");
    try {
      await authApiRequest<UserItem>("/api/auth/admin/users", {
        method: "POST",
        body: JSON.stringify({
          full_name: fullName.trim(),
          email: email.trim(),
          password,
          role: accountRole,
          trustee_id: accountRole === "trustee" ? trusteeId : null,
        }),
      });
      await loadData();
      setFullName(""); setEmail(""); setPassword(""); setTrusteeId("");
      setSuccess("User account created successfully.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "User creation failed.");
    } finally { setBusy(false); }
  }

  async function deactivateUser(userId: string) {
    if (!window.confirm("Deactivate this account? The user will no longer be able to sign in.")) return;
    setBusy(true); setError(""); setSuccess("");
    try {
      await authApiRequest<UserItem>(`/api/auth/admin/users/${encodeURIComponent(userId)}/deactivate`, { method: "POST" });
      await loadData();
      setSuccess("User account deactivated.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to deactivate user.");
    } finally { setBusy(false); }
  }

  return (
    <Page title="Administration" sub="IDENTITY / TRUSTEE DIRECTORY / ACCESS GOVERNANCE">
      {error && <div className="auth-error" role="alert">{error}</div>}
      {success && <div className="admin-success" role="status">{success}</div>}
      <div className="admin-columns">
        <section className="card">
          <small className="eyebrow">TRUSTEE DIRECTORY</small>
          <h3>Create trustee record</h3>
          <p className="muted">Create the trustee identity first. You can then link a trustee login account to this record.</p>
          <form className="admin-form" onSubmit={createTrustee}>
            <label>Trustee name<input required maxLength={120} value={trusteeName} onChange={(event) => setTrusteeName(event.target.value)} /></label>
            <label>Trustee role / description<input required maxLength={80} value={trusteeRole} onChange={(event) => setTrusteeRole(event.target.value)} /></label>
            <label>Ethereum wallet address (optional)<input value={walletAddress} onChange={(event) => setWalletAddress(event.target.value)} placeholder="0x…" /></label>
            <label>Public encryption key (optional)<input value={publicKey} onChange={(event) => setPublicKey(event.target.value)} /></label>
            <button type="submit" disabled={busy}>{busy ? "SAVING…" : "CREATE TRUSTEE RECORD"}</button>
          </form>
        </section>

        <section className="card">
          <small className="eyebrow">ACCOUNT PROVISIONING</small>
          <h3>Create user account</h3>
          <p className="muted">Public registration is owner-only. Admins provision trustee and administrator accounts here.</p>
          <form className="admin-form" onSubmit={createUser}>
            <label>Full name<input required maxLength={120} value={fullName} onChange={(event) => setFullName(event.target.value)} /></label>
            <label>Email<input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
            <label>Temporary password<input required type="password" minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} /></label>
            <label>Account role<select value={accountRole} onChange={(event) => setAccountRole(event.target.value as typeof accountRole)}><option value="owner">Owner</option><option value="trustee">Trustee</option><option value="admin">Administrator</option></select></label>
            {accountRole === "trustee" && <label>Unlinked trustee record<select required value={trusteeId} onChange={(event) => setTrusteeId(event.target.value)}><option value="">Select a trustee</option>{trustees.filter((item) => item.active).map((item) => <option key={item.id} value={item.id}>{item.name} · {item.id}</option>)}</select></label>}
            <button type="submit" disabled={busy || (accountRole === "trustee" && !trusteeId)}>{busy ? "CREATING…" : "CREATE USER ACCOUNT"}</button>
          </form>
        </section>
      </div>

      <section className="card">
        <div className="section-heading"><div><small className="eyebrow">IDENTITY REGISTRY</small><h3>User accounts</h3></div><span>{users.length} total</span></div>
        {loading ? <p>Loading users…</p> : users.length === 0 ? <p className="muted">No user accounts found.</p> : users.map((item) => (
          <div className="row admin-list-row" key={item.id}>
            <span><strong>{item.full_name}</strong><small className="block-muted">{item.email} · {item.role.toUpperCase()}</small></span>
            <span className={item.is_active ? "ok" : "warning-status"}>{item.is_active ? "ACTIVE" : "INACTIVE"}</span>
            {item.is_active && item.id !== currentUser?.id && <button className="small-danger-button" type="button" disabled={busy} onClick={() => void deactivateUser(item.id)}>DEACTIVATE</button>}
          </div>
        ))}
      </section>

      <section className="card">
        <div className="section-heading"><div><small className="eyebrow">TRUSTEE REGISTRY</small><h3>Trustee records</h3></div><span>{trustees.length} total</span></div>
        {loading ? <p>Loading trustees…</p> : trustees.length === 0 ? <p className="muted">No trustee records found.</p> : trustees.map((item) => (
          <div className="row" key={item.id}><span><strong>{item.name}</strong><small className="block-muted">{item.role} · {item.id}</small></span><span className={item.active ? "ok" : "warning-status"}>{item.active ? "ACTIVE" : "INACTIVE"}</span></div>
        ))}
      </section>
    </Page>
  );
}
