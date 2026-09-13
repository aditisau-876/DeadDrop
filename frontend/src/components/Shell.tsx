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
      <aside>
        <div className="brand">
          <b>D</b>

          <div>
            <strong>DeadDrop</strong>
            <small>Emergency Recovery</small>
          </div>
        </div>

        <nav>
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => (isActive ? "active" : "")}
            >
              <Icon size={17} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </aside>

      <main>
        <header>
          <strong>Recovery Control Plane</strong>
          <span>System Operational</span>
        </header>

        <Outlet />
      </main>
    </div>
  );
}