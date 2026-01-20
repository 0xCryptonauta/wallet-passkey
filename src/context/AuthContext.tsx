import React, { createContext, useContext, useState, useEffect } from "react";
import type { ReactNode } from "react";
import { hasRegisteredPasskeys } from "../lib/passkeys";
import type { PasskeyCredential, AuthenticationResult } from "../lib/passkeys";

interface AuthContextType {
  isAuthenticated: boolean;
  isAuthenticating: boolean;
  hasPasskeys: boolean;
  lastAuthTime: number | null;
  authenticate: () => Promise<AuthenticationResult>;
  logout: () => void;
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

export function AuthProvider({ children }: AuthProviderProps) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [hasPasskeys, setHasPasskeys] = useState(false);
  const [lastAuthTime, setLastAuthTime] = useState<number | null>(null);

  // Check for existing passkeys on mount
  useEffect(() => {
    const checkPasskeys = () => {
      const hasKeys = hasRegisteredPasskeys();
      setHasPasskeys(hasKeys);

      // If user has passkeys but isn't authenticated, they need to authenticate
      if (hasKeys && !isAuthenticated) {
        // Could auto-prompt for authentication here, but let's keep it manual for now
      }
    };

    checkPasskeys();

    // Listen for storage changes (in case passkeys are added/removed in another tab)
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === "wallet-passkeys") {
        checkPasskeys();
      }
    };

    window.addEventListener("storage", handleStorageChange);
    return () => window.removeEventListener("storage", handleStorageChange);
  }, [isAuthenticated]);

  const authenticate = async (): Promise<AuthenticationResult> => {
    if (!hasPasskeys) {
      return {
        success: false,
        error: "No passkeys registered. Please register a passkey first.",
      };
    }

    setIsAuthenticating(true);

    try {
      // Import dynamically to avoid issues in environments without WebAuthn
      const { authenticateWithPasskey } = await import("../lib/passkeys");
      const result = await authenticateWithPasskey();

      if (result.success) {
        setIsAuthenticated(true);
        setLastAuthTime(Date.now());
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
  };

  const value: AuthContextType = {
    isAuthenticated,
    isAuthenticating,
    hasPasskeys,
    lastAuthTime,
    authenticate,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
