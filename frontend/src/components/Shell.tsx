
import { NavLink, Outlet } from "react-router-dom";

import {
  LayoutDashboard,
  FileKey2,
  LockKeyhole,
  ShieldCheck,
} from "lucide-react";

const links = [
  {
    to: "/dashboard",
    label: "Dashboard",
    icon: LayoutDashboard,
  },
  {
    to: "/policies",
    label: "Policies",
    icon: FileKey2,
  },
  {
    to: "/recovery",
    label: "Recovery",
    icon: LockKeyhole,
  },
  {
    to: "/readiness",
    label: "Readiness",
    icon: ShieldCheck,
  },
];

export function Shell() {
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <b className="brand-logo">D</b>

          <div className="brand-info">
            <strong>DeadDrop</strong>
            <small>Emergency Recovery</small>
          </div>
        </div>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="sidebar-nav">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                isActive ? "nav-link active" : "nav-link"
              }
            >
              <Icon size={18} strokeWidth={1.9} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span className="sidebar-status-dot" />
          <span>Protocol Environment</span>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <strong>Recovery Control Plane</strong>
            <small>DeadDrop / Security Console</small>
          </div>

          <div className="system-status">
            <span className="status-dot" />
            System Operational
          </div>
        </header>

        <div className="content-area">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
