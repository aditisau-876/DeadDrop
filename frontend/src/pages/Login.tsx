import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email.trim(), password);
      const destination = (location.state as { from?: string } | null)?.from || "/dashboard";
      navigate(destination, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-screen">
      <section className="auth-panel">
        <div className="auth-kicker">DEADDROP / SECURE ACCESS</div>
        <div className="auth-symbol">D<span>.</span></div>
        <p className="auth-overline">IDENTITY VERIFICATION</p>
        <h1>Welcome<br />back.</h1>
        <p className="auth-description">Sign in to access your protected assets and recovery console.</p>
        <form className="auth-form" onSubmit={handleSubmit}>
          <label>Email address<input type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" /></label>
          <label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" /></label>
          {error && <div className="auth-error" role="alert">{error}</div>}
          <button type="submit" disabled={loading}>{loading ? "AUTHENTICATING..." : "SIGN IN →"}</button>
        </form>
        <p className="auth-switch">New to DeadDrop? <Link to="/register">Create an owner account</Link></p>
        <div className="auth-footnote">YOUR SESSION IS ENCRYPTED IN TRANSIT · ACCESS IS ROLE-RESTRICTED</div>
      </section>
      <aside className="auth-aside"><span>01 / TRUST</span><div className="auth-aside-mark">⌘</div><h2>Recovery should never depend on a single point of failure.</h2><p>Distributed trust. Verifiable authorization. Controlled recovery.</p></aside>
    </main>
  );
}
