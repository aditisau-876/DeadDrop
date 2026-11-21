import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  getStoredToken,
  setStoredToken,
  clearStoredToken,
} from "../lib/authStorage";

import { authApiRequest } from "../lib/authApi";

export type UserRole = "admin" | "owner" | "trustee";

export interface AuthUser {
  id: number | string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  trustee_id?: number | string | null;
}

interface LoginCredentials {
  email: string;
  password: string;
}

interface RegisterDetails {
  email: string;
  password: string;
  full_name: string;
}

interface AuthContextValue {
  user: AuthUser | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (details: RegisterDetails) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(
  undefined
);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    const token = getStoredToken();

    if (!token) {
      setUser(null);
      setIsLoading(false);
      return;
    }

    try {
      const currentUser = await authApiRequest<AuthUser>("/auth/me");
      setUser(currentUser);
    } catch {
      clearStoredToken();
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshUser();
  }, [refreshUser]);

  const login = useCallback(
    async (credentials: LoginCredentials) => {
      const response = await authApiRequest<{
        access_token: string;
        token_type: string;
        user: AuthUser;
      }>("/auth/login", {
        method: "POST",
        body: JSON.stringify(credentials),
      });

      setStoredToken(response.access_token);
      setUser(response.user);

      // Verify the session against the backend.
      await refreshUser();
    },
    [refreshUser]
  );

  const register = useCallback(
    async (details: RegisterDetails) => {
      await authApiRequest<AuthUser>("/auth/register", {
        method: "POST",
        body: JSON.stringify(details),
      });

      // Registration creates the account; it does not automatically
      // authenticate the user. Log in separately.
    },
    []
  );

  const logout = useCallback(() => {
    clearStoredToken();
    setUser(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isLoading,
      isAuthenticated: Boolean(user),
      login,
      register,
      logout,
      refreshUser,
    }),
    [user, isLoading, login, register, logout, refreshUser]
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error(
      "useAuth must be used inside an AuthProvider"
    );
  }

  return context;
}
