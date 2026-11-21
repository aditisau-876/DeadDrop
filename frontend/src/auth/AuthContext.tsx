import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { authApiRequest } from "../lib/authApi";
import {
  clearAccessToken,
  getAccessToken,
  saveAccessToken,
} from "./authStorage";

export type UserRole = "owner" | "trustee" | "admin";

export interface AuthUser {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
}

interface AuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: AuthUser;
}

interface AuthContextValue {
  user: AuthUser | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (fullName: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    const token = getAccessToken();
    if (!token) {
      setUser(null);
      setIsLoading(false);
      return;
    }

    try {
      const currentUser = await authApiRequest<AuthUser>("/api/auth/me");
      setUser(currentUser);
    } catch {
      clearAccessToken();
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshUser();
  }, [refreshUser]);

  const login = useCallback(async (email: string, password: string) => {
    const result = await authApiRequest<AuthTokenResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email: email.trim(), password }),
    });
    saveAccessToken(result.access_token);
    setUser(result.user);
  }, []);

  const register = useCallback(async (fullName: string, email: string, password: string) => {
    // The backend returns a token response and signs the new owner in.
    const result = await authApiRequest<AuthTokenResponse>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        full_name: fullName.trim(),
        email: email.trim(),
        password,
      }),
    });
    saveAccessToken(result.access_token);
    setUser(result.user);
  }, []);

  const logout = useCallback(() => {
    clearAccessToken();
    setUser(null);
  }, []);

  const value = useMemo<AuthContextValue>(() => ({
    user,
    isLoading,
    isAuthenticated: Boolean(user),
    login,
    register,
    logout,
    refreshUser,
  }), [user, isLoading, login, register, logout, refreshUser]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider.");
  return context;
}
