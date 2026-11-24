import { Navigate, Route, Routes } from "react-router-dom";

import { AuthProvider } from "./auth/AuthContext";
import { ProtectedRoute } from "./auth/ProtectedRoute";
import { Shell } from "./components/Shell";
import { Dashboard } from "./pages/Dashboard";
import { Admin } from "./pages/Admin";
import { Assets } from "./pages/Assets";
import { Login } from "./pages/Login";
import { Policies } from "./pages/Policies";
import { Readiness } from "./pages/Readiness";
import { Recovery } from "./pages/Recovery";
import { ShareRotation } from "./pages/ShareRotation";
import { Register } from "./pages/Register";
import { TrusteeApprovals } from "./pages/TrusteeApprovals";

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        <Route element={<ProtectedRoute />}>
          <Route element={<Shell />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/recovery" element={<Recovery />} />

            <Route
              element={<ProtectedRoute allowedRoles={["owner", "admin"]} />}
            >
              <Route path="/rotation" element={<ShareRotation />} />
            </Route>

            <Route path="/readiness" element={<Readiness />} />

            <Route element={<ProtectedRoute allowedRoles={["trustee"]} />}>
              <Route path="/trustee-approvals" element={<TrusteeApprovals />} />
            </Route>

            <Route element={<ProtectedRoute allowedRoles={["admin"]} />}>
              <Route path="/admin" element={<Admin />} />
            </Route>

            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Route>
      </Routes>
    </AuthProvider>
  );
}