import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    if (password.length < 12) { setError("Password must contain at least 12 characters."); return; }
    if (password !== confirmPassword) { setError("The passwords do not match."); return; }
    setLoading(true);
    try {
      await register(fullName.trim(), email.trim(), password);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Account creation failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-screen auth-screen-register">
      <section className="auth-panel">
        <div className="auth-kicker">DEADDROP / CREATE IDENTITY</div>
        <div className="auth-symbol">D<span>.</span></div>
        <p className="auth-overline">OWNER REGISTRATION</p>
        <h1>Establish<br />your access.</h1>
        <p className="auth-description">Create an owner account to begin protecting and managing recovery policies.</p>
        <form className="auth-form" onSubmit={handleSubmit}>
          <label>Full name<input autoComplete="name" required maxLength={120} value={fullName} onChange={(event) => setFullName(event.target.value)} placeholder="Your full name" /></label>
          <label>Email address<input type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" /></label>
          <label>Password<input type="password" autoComplete="new-password" required minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="At least 12 characters" /></label>
          <label>Confirm password<input type="password" autoComplete="new-password" required value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Re-enter your password" /></label>
          {error && <div className="auth-error" role="alert">{error}</div>}
          <button type="submit" disabled={loading}>{loading ? "CREATING ACCOUNT..." : "CREATE OWNER ACCOUNT →"}</button>
        </form>
        <p className="auth-switch">Already registered? <Link to="/login">Sign in</Link></p>
        <div className="auth-footnote">PUBLIC SIGN-UP CREATES OWNER ACCOUNTS ONLY · TRUSTEE / ADMIN ACCOUNTS ARE PROVISIONED BY AN ADMIN</div>
      </section>
      <aside className="auth-aside"><span>02 / CONTROL</span><div className="auth-aside-mark">◇</div><h2>Access is granted by identity, bounded by role.</h2><p>Every protected action is checked by the backend before it is allowed.</p></aside>
    </main>
  );
}
