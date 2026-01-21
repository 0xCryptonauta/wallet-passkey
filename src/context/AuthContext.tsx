import { createContext, useContext, useState, useEffect } from "react";
import { useAccount } from "wagmi";
import type { ReactNode } from "react";
import { hasRegisteredPasskeys } from "../lib/passkeys";
import type { AuthenticationResult } from "../lib/passkeys";

interface AuthContextType {
  isAuthenticated: boolean;
  isAuthenticating: boolean;
  hasPasskeys: boolean;
  lastAuthTime: number | null;
  currentWalletAddress: string | null;
  masterKey: Uint8Array | null;
  authenticate: (walletAddress?: string) => Promise<AuthenticationResult>;
  logout: () => void;
  refreshPasskeys: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

interface AuthProviderProps {
  children: ReactNode;
}

// Authentication persistence helpers
const AUTH_STORAGE_KEY = "wallet-auth-state";

interface PersistedAuthState {
  isAuthenticated: boolean;
  lastAuthTime: number;
  walletAddress: string;
}

function saveAuthState(
  isAuthenticated: boolean,
  lastAuthTime: number | null,
  walletAddress: string | null,
) {
  if (isAuthenticated && lastAuthTime && walletAddress) {
    const state: PersistedAuthState = {
      isAuthenticated: true,
      lastAuthTime,
      walletAddress,
    };
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(state));
  } else {
    localStorage.removeItem(AUTH_STORAGE_KEY);
  }
}

function loadAuthState(): PersistedAuthState | null {
  try {
    const stored = localStorage.getItem(AUTH_STORAGE_KEY);
    if (!stored) return null;

    const state: PersistedAuthState = JSON.parse(stored);

    // Expire authentication after 24 hours for security
    const EXPIRY_TIME = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
    if (Date.now() - state.lastAuthTime > EXPIRY_TIME) {
      localStorage.removeItem(AUTH_STORAGE_KEY);
      return null;
    }

    return state;
  } catch (error) {
    console.error("Failed to load auth state:", error);
    localStorage.removeItem(AUTH_STORAGE_KEY);
    return null;
  }
}

export function AuthProvider({ children }: AuthProviderProps) {
  const { address, isConnected } = useAccount();

  // Initialize state from localStorage if available
  const persistedState = loadAuthState();
  const [isAuthenticated, setIsAuthenticated] = useState(
    persistedState?.isAuthenticated || false,
  );
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [hasPasskeys, setHasPasskeys] = useState(false);
  const [lastAuthTime, setLastAuthTime] = useState<number | null>(
    persistedState?.lastAuthTime || null,
  );
  const [currentWalletAddress, setCurrentWalletAddress] = useState<
    string | null
  >(persistedState?.walletAddress || null);
  const [masterKey, setMasterKey] = useState<Uint8Array | null>(null);

  // Check for existing passkeys on mount and when storage changes
  useEffect(() => {
    const checkPasskeys = () => {
      // Check if any passkeys exist at all (not wallet-specific)
      const allCredentials = JSON.parse(
        localStorage.getItem("wallet-passkeys-v2") || "{}",
      );
      const hasAnyKeys = Object.keys(allCredentials).length > 0;
      setHasPasskeys(hasAnyKeys);

      // If user has passkeys but isn't authenticated, they need to authenticate
      if (hasAnyKeys && !isAuthenticated) {
        // Could auto-prompt for authentication here, but let's keep it manual for now
      }
    };

    checkPasskeys();

    // Listen for storage changes (in case passkeys are added/removed in another tab)
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === "wallet-passkeys-v2") {
        checkPasskeys();
      }
    };

    window.addEventListener("storage", handleStorageChange);
    return () => window.removeEventListener("storage", handleStorageChange);
  }, []); // Run on mount only, not when isAuthenticated changes

  // Wallet change detection - keep passkey sessions independent of wallet connection
  useEffect(() => {
    // If wallet address changed while connected, logout passkey session (don't clear passkeys)
    if (
      isConnected &&
      address &&
      currentWalletAddress &&
      address !== currentWalletAddress
    ) {
      // Wallet address changed, logout but keep all passkeys
      console.log(`🔄 Switching wallets: ${currentWalletAddress} → ${address}`);
      console.log(" Keeping all passkeys for convenience");
      setIsAuthenticated(false);
      setLastAuthTime(null);
      // Don't clear passkeys - they persist across wallet switches
    }

    // Update current wallet address only when wallet is connected
    if (isConnected && address && address !== currentWalletAddress) {
      setCurrentWalletAddress(address);
      // Refresh passkeys for the new wallet
      setHasPasskeys(hasRegisteredPasskeys(address));
    }
  }, [address, isConnected, currentWalletAddress]);

  const authenticate = async (
    walletAddress?: string,
  ): Promise<AuthenticationResult> => {
    // Use provided wallet address (from passkey) - don't require current wallet connection
    const authAddress = walletAddress;

    if (!authAddress) {
      return {
        success: false,
        error: "No wallet address provided for authentication.",
      };
    }

    // Check if the specified wallet has passkeys
    const walletHasPasskeys = hasRegisteredPasskeys(authAddress);
    if (!walletHasPasskeys) {
      return {
        success: false,
        error: `No passkeys registered for wallet ${authAddress.slice(
          0,
          6,
        )}...${authAddress.slice(-4)}. Please register a passkey first.`,
      };
    }

    setIsAuthenticating(true);

    try {
      // Import dynamically to avoid issues in environments without WebAuthn
      const { authenticateWithPasskey } = await import("../lib/passkeys");
      const result = await authenticateWithPasskey(authAddress);

      if (result.success && result.masterKey) {
        // Use the master key returned from authentication
        setMasterKey(result.masterKey);

        const authTime = Date.now();
        setIsAuthenticated(true);
        setLastAuthTime(authTime);
        setCurrentWalletAddress(authAddress);
        // Persist authentication state
        saveAuthState(true, authTime, authAddress);
      }

      return result;
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Authentication failed",
      };
    } finally {
      setIsAuthenticating(false);
    }
  };

  const logout = () => {
    setIsAuthenticated(false);
    setLastAuthTime(null);
    setCurrentWalletAddress(null);
    setMasterKey(null);
    // Clear persisted authentication state
    saveAuthState(false, null, null);
  };

  const refreshPasskeys = () => {
    const hasKeys = hasRegisteredPasskeys(address || undefined);
    setHasPasskeys(hasKeys);
  };

  const value: AuthContextType = {
    isAuthenticated,
    isAuthenticating,
    hasPasskeys,
    lastAuthTime,
    currentWalletAddress,
    masterKey,
    authenticate,
    logout,
    refreshPasskeys,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
