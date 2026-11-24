
import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

const ownerLinks = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/policies", label: "Policies" },
  { to: "/assets", label: "Protected Assets" },
  { to: "/readiness", label: "Readiness" },
  { to: "/recovery", label: "Recovery" },
];

const trusteeLinks = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/trustee-approvals", label: "Approval Inbox" },
  { to: "/recovery", label: "Share Release" },
];

const adminLinks = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/policies", label: "Policies" },
  { to: "/assets", label: "Protected Assets" },
  { to: "/readiness", label: "Readiness" },
  { to: "/recovery", label: "Recovery" },
  { to: "/admin", label: "Administration" },
];

const DEAD_DROP_CHAIN_ID = "0x7a69"; // 31337
const DEAD_DROP_CHAIN_NUMBER = 31337;

function DeadDropMark() {
  return (
    <svg
      className="console-mark"
      viewBox="0 0 46 46"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <polyline points="18,7 23,13 28,7" stroke="currentColor" strokeWidth="3" />
      <polyline points="18,39 23,33 28,39" stroke="currentColor" strokeWidth="3" />
      <polyline points="7,18 13,23 7,28" stroke="currentColor" strokeWidth="3" />
      <polyline points="39,18 33,23 39,28" stroke="currentColor" strokeWidth="3" />
      <rect
        x="18.5"
        y="18.5"
        width="9"
        height="9"
        stroke="currentColor"
        strokeWidth="3"
      />
    </svg>
  );
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return "Wallet connection failed. Please try again.";
}

export function Shell() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const [walletAddress, setWalletAddress] = useState<string | null>(null);
  const [chainId, setChainId] = useState<string | null>(null);
  const [walletError, setWalletError] = useState("");

  const links =
    user?.role === "admin"
      ? adminLinks
      : user?.role === "trustee"
        ? trusteeLinks
        : ownerLinks;

  useEffect(() => {
    const provider = window.ethereum;

    if (!provider) return;

    const loadWallet = async () => {
      try {
        const accounts = (await provider.request({
          method: "eth_accounts",
        })) as string[];

        const currentChain = (await provider.request({
          method: "eth_chainId",
        })) as string;

        setWalletAddress(accounts?.[0] ?? null);
        setChainId(currentChain);
      } catch {
        // Wallet is not available or has not been initialized.
      }
    };

    const handleAccountsChanged = (...args: unknown[]) => {
      const accounts = args[0] as string[];
      setWalletAddress(accounts?.[0] ?? null);
    };

    const handleChainChanged = (...args: unknown[]) => {
      setChainId(args[0] as string);
    };

    void loadWallet();

    provider.on?.("accountsChanged", handleAccountsChanged);
    provider.on?.("chainChanged", handleChainChanged);

    return () => {
      provider.removeListener?.("accountsChanged", handleAccountsChanged);
      provider.removeListener?.("chainChanged", handleChainChanged);
    };
  }, []);

  async function switchToDeadDropNetwork(provider: NonNullable<Window["ethereum"]>) {
    try {
      await provider.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: DEAD_DROP_CHAIN_ID }],
      });
    } catch (error) {
      const walletError = error as { code?: number };

      if (walletError.code !== 4902) {
        throw error;
      }

      await provider.request({
        method: "wallet_addEthereumChain",
        params: [
          {
            chainId: DEAD_DROP_CHAIN_ID,
            chainName: "DeadDrop Local",
            nativeCurrency: {
              name: "Ether",
              symbol: "ETH",
              decimals: 18,
            },
            rpcUrls: ["http://127.0.0.1:8545"],
          },
        ],
      });
    }

    setChainId(DEAD_DROP_CHAIN_ID);
  }

  async function handleConnectWallet() {
    const provider = window.ethereum;

    setWalletError("");

    if (!provider) {
      setWalletError("MetaMask was not detected. Please install or enable MetaMask.");
      return;
    }

    try {
      const accounts = (await provider.request({
        method: "eth_requestAccounts",
      })) as string[];

      if (!accounts || accounts.length === 0) {
        setWalletError("No wallet account was selected.");
        return;
      }

      setWalletAddress(accounts[0]);

      const currentChain = (await provider.request({
        method: "eth_chainId",
      })) as string;

      setChainId(currentChain);

      if (currentChain !== DEAD_DROP_CHAIN_ID) {
        await switchToDeadDropNetwork(provider);
      }
    } catch (error) {
      setWalletError(getErrorMessage(error));
    }
  }

  async function handleSwitchNetwork() {
    const provider = window.ethereum;

    if (!provider) return;

    setWalletError("");

    try {
      await switchToDeadDropNetwork(provider);
    } catch (error) {
      setWalletError(getErrorMessage(error));
    }
  }

  function handleDisconnectWallet() {
    // This clears the connection shown by DeadDrop.
    // MetaMask permissions themselves are not revoked.
    setWalletAddress(null);
    setWalletError("");
  }

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  const shortAddress = walletAddress
    ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`
    : "";

  return (
    <div className="console-shell">
      <header className="console-header">
        <NavLink
          className="console-brand"
          to="/dashboard"
          aria-label="DeadDrop dashboard"
        >
          <DeadDropMark />
          <span className="console-wordwrap">
            <span className="console-word">DeadDrop</span>
            <span className="console-brand-caption">RECOVERY PROTOCOL</span>
          </span>
        </NavLink>

        <nav className="console-nav" aria-label="Console navigation">
          {links.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                isActive
                  ? "console-nav-link active"
                  : "console-nav-link"
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="console-header-actions">
          <div className="console-wallet-area">
            {walletAddress ? (
              <>
                <div className="console-wallet-info">
                  <span className="console-wallet-indicator" />
                  <span className="console-wallet-address">
                    {shortAddress}
                  </span>
                </div>

                {chainId !== DEAD_DROP_CHAIN_ID && (
                  <button
                    className="console-wallet-button"
                    type="button"
                    onClick={handleSwitchNetwork}
                  >
                    SWITCH NETWORK
                  </button>
                )}

                {chainId === DEAD_DROP_CHAIN_ID && (
                  <span className="console-wallet-network">
                    LOCAL · {DEAD_DROP_CHAIN_NUMBER}
                  </span>
                )}

                <button
                  className="console-wallet-disconnect"
                  type="button"
                  onClick={handleDisconnectWallet}
                >
                  DISCONNECT
                </button>
              </>
            ) : (
              <button
                className="console-wallet-button"
                type="button"
                onClick={handleConnectWallet}
              >
                <span aria-hidden="true">◇</span>
                CONNECT WALLET
              </button>
            )}

            {walletError && (
              <span className="console-wallet-error" role="alert">
                {walletError}
              </span>
            )}
          </div>

          <div className="console-user-area">
            <div className="console-user-copy">
              <strong>{user?.full_name}</strong>
              <span>{user?.role?.toUpperCase()} ACCESS</span>
            </div>

            <button
              className="console-logout"
              type="button"
              onClick={handleLogout}
            >
              SIGN OUT
            </button>
          </div>
        </div>
      </header>

      <main className="console-main">
        <Outlet />
      </main>
    </div>
  );
}
