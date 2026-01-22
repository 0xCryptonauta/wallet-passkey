import { useState, useEffect } from "react";
import { useSignMessage, useAccount } from "wagmi";
import {
  registerPasskey,
  getStoredCredentials,
  deletePasskey,
  isMobileDevice,
  isWebAuthnSupported,
} from "../lib/passkeys";
import type { AuthenticationResult } from "../lib/passkeys";
import { useAuth } from "../context/AuthContext";
import { Account } from "./Account";

export function PasskeyAuth() {
  const {
    isAuthenticated,
    isAuthenticating,
    hasPasskeys,
    authenticate,
    logout,
    refreshPasskeys,
    currentWalletAddress,
  } = useAuth();
  const { signMessageAsync } = useSignMessage();
  const { address, isConnected } = useAccount();
  const [isRegistering, setIsRegistering] = useState(false);
  const [authMessage, setAuthMessage] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [forceUpdate, setForceUpdate] = useState(0);
  const [showTooltip, setShowTooltip] = useState(false);
  const [showInstallPrompt, setShowInstallPrompt] = useState(false);
  const [deferredPrompt, setDeferredPrompt] = useState<any>(null);
  const [isInstalled, setIsInstalled] = useState(false);
  const [platformAuthAvailable, setPlatformAuthAvailable] = useState<
    boolean | null
  >(null);

  // Detect device capabilities and PWA install prompt on mount
  useEffect(() => {
    const detectCapabilities = async () => {
      const capabilities = {
        isWebAuthnSupported: isWebAuthnSupported(),
        isPlatformAuthAvailable: false,
        isMobile: isMobileDevice(),
      };

      try {
        const { isPlatformAuthenticatorAvailable } =
          await import("../lib/passkeys");
        capabilities.isPlatformAuthAvailable =
          await isPlatformAuthenticatorAvailable();
        setPlatformAuthAvailable(capabilities.isPlatformAuthAvailable);
      } catch (error) {
        console.warn(
          "Failed to check platform authenticator availability:",
          error,
        );
        setPlatformAuthAvailable(false);
      }
    };

    detectCapabilities();

    // PWA Install Prompt Logic
    const handleBeforeInstallPrompt = (e: Event) => {
      // Prevent the mini-infobar from appearing on mobile
      e.preventDefault();
      // Store the event so it can be triggered later
      setDeferredPrompt(e as any);
      // Show the install prompt
      setShowInstallPrompt(true);
    };

    const handleAppInstalled = () => {
      // Hide the install prompt
      setShowInstallPrompt(false);
      setIsInstalled(true);
      setDeferredPrompt(null);
    };

    // Check if already installed
    if (window.matchMedia("(display-mode: standalone)").matches) {
      setIsInstalled(true);
    }

    window.addEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
    window.addEventListener("appinstalled", handleAppInstalled);

    return () => {
      window.removeEventListener(
        "beforeinstallprompt",
        handleBeforeInstallPrompt,
      );
      window.removeEventListener("appinstalled", handleAppInstalled);
    };
  }, []);

  const handleRegister = async () => {
    if (!address) {
      setAuthError("Please connect your wallet first");
      return;
    }

    setIsRegistering(true);
    setAuthError(null);
    setAuthMessage("Signing message with wallet...");

    try {
      // First sign the challenge with the wallet
      const walletSignMessage = async (message: string): Promise<string> => {
        return await signMessageAsync({ message });
      };

      setAuthMessage("Creating passkey...");
      const result: AuthenticationResult = await registerPasskey(
        walletSignMessage,
        address,
      );

      if (result.success) {
        setAuthMessage(
          "Passkey created successfully! You can now authenticate.",
        );
        // Refresh the passkeys state to update the UI immediately
        refreshPasskeys();
      } else {
        setAuthError(result.error || "Registration failed");
      }
    } catch (error) {
      setAuthError("An unexpected error occurred during registration");
    } finally {
      setIsRegistering(false);
      setAuthMessage(null);
    }
  };

  const handleAuthenticateWithWallet = async (walletAddress: string) => {
    setAuthError(null);
    setAuthMessage(
      `Authenticating with ${walletAddress.slice(0, 6)}...${walletAddress.slice(
        -4,
      )} passkey...`,
    );

    const result = await authenticate(walletAddress);

    if (result.success) {
      setAuthMessage("Authentication successful!");
      // Force a re-render by updating local state
      setAuthError(null);
      setForceUpdate((prev) => prev + 1);
      setTimeout(() => setAuthMessage(null), 2000);
    } else {
      setAuthError(result.error || "Authentication failed");
    }
  };

  const handleLogout = () => {
    logout();
    setAuthMessage("Logged out successfully");
    setTimeout(() => setAuthMessage(null), 2000);
  };

  const handleDeletePasskey = (credentialId: string) => {
    if (
      window.confirm(
        "Are you sure you want to delete this passkey? This action cannot be undone.",
      )
    ) {
      const success = deletePasskey(credentialId, address);
      if (success) {
        setAuthMessage("Passkey deleted successfully");
        refreshPasskeys(); // Update the passkeys state
        setTimeout(() => setAuthMessage(null), 2000);
      } else {
        setAuthError("Failed to delete passkey");
      }
    }
  };

  const handleInstallPWA = async () => {
    if (!deferredPrompt) return;

    // Show the install prompt
    deferredPrompt.prompt();

    // Wait for the user to respond to the prompt
    await deferredPrompt.userChoice;

    // Reset the deferred prompt
    setDeferredPrompt(null);
    setShowInstallPrompt(false);

    // User responded to install prompt
  };

  const dismissInstallPrompt = () => {
    setShowInstallPrompt(false);
  };

  return (
    <div className="max-w-2xl mx-auto py-12 px-4">
      <div className="bg-white p-8 rounded-lg border border-slate-200">
        {/* Wallet Section */}
        <div className="mb-8">
          <h2 className="text-xl font-semibold mb-6 text-slate-900">Wallet</h2>
          <Account />
        </div>

        <div className="mb-8">
          <h2 className="text-xl font-semibold mb-6 text-slate-900">
            Passkey Authentication
          </h2>
        </div>

        {/* Status Section */}
        <div className="mb-8">
          <div className="flex items-center gap-6 text-sm text-slate-600">
            <div className="flex items-center gap-3">
              <span
                className={`w-3 h-3 rounded-full ${
                  isAuthenticated ? "bg-green-500" : "bg-slate-300"
                }`}
              ></span>
              <span>Authenticated: {isAuthenticated ? "Yes" : "No"}</span>
            </div>
            <div className="flex items-center gap-3">
              <span
                className={`w-3 h-3 rounded-full ${
                  hasPasskeys ? "bg-green-500" : "bg-slate-300"
                }`}
              ></span>
              <span>Passkeys: {hasPasskeys ? "Yes" : "No"}</span>
            </div>
          </div>
        </div>

        {/* Registered Passkeys Section */}
        {hasPasskeys && (
          <div className="mb-8">
            <h3 className="text-lg font-medium mb-4 text-slate-900">
              Registered Passkeys
            </h3>
            <div className="space-y-4">
              {getStoredCredentials(address || undefined).map(
                (credential, index) => (
                  <div
                    key={credential.id}
                    className="p-4 border border-slate-200 rounded-md"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="font-medium text-sm text-slate-900 mb-1">
                          Passkey #{index + 1}
                        </div>
                        <div className="text-xs text-slate-600 font-mono">
                          {credential.walletAddress
                            ? `${credential.walletAddress.slice(0, 8)}...${credential.walletAddress.slice(-6)}`
                            : "Legacy passkey"}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                          {new Date(credential.created).toLocaleDateString()}
                        </div>
                      </div>

                      <div className="flex flex-col gap-2 ml-4">
                        {isAuthenticated &&
                        currentWalletAddress === credential.walletAddress ? (
                          <button
                            onClick={handleLogout}
                            className="px-4 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 transition cursor-pointer font-medium"
                          >
                            Logout
                          </button>
                        ) : (
                          <button
                            onClick={() =>
                              handleAuthenticateWithWallet(
                                credential.walletAddress,
                              )
                            }
                            disabled={isAuthenticating}
                            className="px-4 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer font-medium"
                          >
                            {isAuthenticating ? "Authenticating..." : "Login"}
                          </button>
                        )}

                        <button
                          onClick={() => handleDeletePasskey(credential.id)}
                          className="px-3 py-1 text-xs bg-red-600 text-white rounded hover:bg-red-700 transition cursor-pointer"
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  </div>
                ),
              )}
            </div>
          </div>
        )}

        {/* Messages */}
        {authMessage && (
          <div className="mb-6 p-3 bg-slate-50 border border-slate-200 rounded-md">
            <p className="text-slate-700 text-sm">{authMessage}</p>
          </div>
        )}

        {authError && (
          <div className="mb-6 p-3 bg-slate-50 border border-slate-200 rounded-md">
            <p className="text-slate-700 text-sm">{authError}</p>
          </div>
        )}

        {/* Registration Section */}
        {isConnected && !hasPasskeys && (
          <div>
            <h3 className="text-lg font-medium mb-3 text-slate-900">
              Create Passkey
            </h3>
            <p className="text-sm text-slate-600 mb-6">
              Create a passkey to secure your wallet operations using your
              device's biometric authentication.
            </p>
            <button
              onClick={handleRegister}
              disabled={isRegistering}
              className="w-full bg-slate-900 text-white px-6 py-3 rounded-md font-medium hover:bg-slate-800 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isRegistering ? "Creating Passkey..." : "Create Passkey"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
