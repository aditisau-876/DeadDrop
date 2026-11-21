import { NavLink, Outlet } from "react-router-dom";

const links = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/policies", label: "Policies" },
  { to: "/recovery", label: "Recovery" },
  { to: "/readiness", label: "Readiness" },
];

function DeadDropMark() {
  return (
    <svg
      className="console-mark"
      viewBox="0 0 46 46"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <polyline points="18,7 23,13 28,7" stroke="currentColor" strokeWidth="3" strokeLinecap="butt" strokeLinejoin="miter" />
      <polyline points="18,39 23,33 28,39" stroke="currentColor" strokeWidth="3" strokeLinecap="butt" strokeLinejoin="miter" />
      <polyline points="7,18 13,23 7,28" stroke="currentColor" strokeWidth="3" strokeLinecap="butt" strokeLinejoin="miter" />
      <polyline points="39,18 33,23 39,28" stroke="currentColor" strokeWidth="3" strokeLinecap="butt" strokeLinejoin="miter" />
      <rect x="18.5" y="18.5" width="9" height="9" stroke="currentColor" strokeWidth="3" />
    </svg>
  );
}

export function Shell() {
  return (
    <div className="console-shell">
      <header className="console-header">
        <a className="console-brand" href="/" aria-label="DeadDrop home">
          <DeadDropMark />
          <span className="console-wordwrap">
            <span className="console-word">DeadDrop</span>
            <span className="console-brand-caption">RECOVERY PROTOCOL</span>
          </span>
        </a>

        <nav className="console-nav" aria-label="Console navigation">
          {links.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                isActive ? "console-nav-link active" : "console-nav-link"
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="console-header-meta">
          <span className="console-status-dot" />
          <span>SECURE CONSOLE</span>
        </div>
      </header>

      <main className="console-main">
        <Outlet />
      </main>
    </div>
  );
}
