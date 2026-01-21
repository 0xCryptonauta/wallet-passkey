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
      } catch (error) {
        console.warn(
          "Failed to check platform authenticator availability:",
          error,
        );
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
    <div className="max-w-2xl mx-auto py-6 px-4">
      <div className="flex flex-col items-center bg-white p-6 rounded-2xl shadow-sm border border-gray-100">
        {/* Wallet Section */}
        <div className="flex flex-col items-center mb-6">
          <h2 className="text-2xl font-bold mb-6 text-right">Wallet</h2>
          <Account />
        </div>

        <div className="relative mb-6">
          <h2 className="text-2xl font-bold inline-flex items-center gap-2">
            Passkey Authentication
            <button
              className="text-gray-400 hover:text-gray-600 transition text-lg"
              onClick={() => setShowTooltip(!showTooltip)}
            >
              ⓘ
            </button>
          </h2>
          {showTooltip && (
            <div className="absolute top-full left-0 mt-2 p-4 bg-gray-900 text-white rounded-lg shadow-lg z-10 max-w-sm">
              <h4 className="font-semibold mb-2">About Passkeys</h4>
              <ul className="text-sm space-y-1">
                <li>
                  • Passkeys use hardware-backed security for phishing-resistant
                  authentication
                </li>
                <li>
                  • They work with Touch ID, Face ID, Windows Hello, or hardware
                  security keys
                </li>
                <li>
                  • No passwords needed - authentication happens directly on
                  your device
                </li>
                <li>
                  • Credentials are stored securely and cannot be exported
                </li>
              </ul>
              <button
                className="absolute top-2 right-2 text-gray-400 hover:text-white"
                onClick={() => setShowTooltip(false)}
              >
                ×
              </button>
            </div>
          )}
        </div>

        {/* Status Section */}
        <div
          key={`status-${forceUpdate}`}
          className="mb-6 p-4 bg-gray-50 rounded-lg"
        >
          <h3 className="font-semibold mb-2">Status</h3>
          <div className="space-y-1 text-sm">
            <div className="flex items-center gap-2">
              <span
                className={`w-2 h-2 rounded-full ${
                  isAuthenticated ? "bg-green-500" : "bg-gray-300"
                }`}
              ></span>
              <span>Authenticated: {isAuthenticated ? "Yes" : "No"}</span>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`w-2 h-2 rounded-full ${
                  hasPasskeys ? "bg-green-500" : "bg-gray-300"
                }`}
              ></span>
              <span>Passkeys registered: {hasPasskeys ? "Yes" : "No"}</span>
            </div>
          </div>
        </div>

        {/* Registered Passkeys Section */}
        {hasPasskeys && (
          <div className="flex flex-col items-center mb-6">
            <h2 className="text-2xl font-bold inline-flex items-center gap-2">
              Registered Passkeys
            </h2>
            <br />
            <div className="space-y-3">
              {getStoredCredentials(address || undefined).map(
                (credential, index) => (
                  <div
                    key={credential.id}
                    className="p-4 border border-gray-200 rounded-lg bg-gray-50 min-w-[300px]"
                  >
                    {/* Two-state layout: stacked on mobile, 2-column on larger screens */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-center">
                      {/* Left Column - Info */}
                      <div className="space-y-3 mb-4 flex flex-col items-center">
                        <div className="font-medium text-sm">
                          Passkey #{index + 1}
                        </div>
                        <div className="flex flex-col items-center text-xs text-gray-600">
                          <span className="font-medium">Wallet:</span>
                          <code className="bg-blue-100 text-blue-800 px-1 py-0.5 rounded text-xs">
                            {credential.walletAddress
                              ? `${credential.walletAddress.slice(
                                  0,
                                  10,
                                )}...${credential.walletAddress.slice(-6)}`
                              : "Legacy passkey"}
                          </code>
                        </div>
                        <div className="flex flex-col items-center text-xs text-gray-600">
                          <span className="font-medium">Credential ID:</span>
                          <code className="bg-gray-100 px-1 py-0.5 rounded text-xs">
                            {credential.id.substring(0, 20)}...
                          </code>
                        </div>
                      </div>

                      {/* Right Column - Date and Actions */}
                      <div className="flex flex-col items-center justify-evenly h-full">
                        <div className="text-xs text-gray-500 mb-3">
                          Created:{" "}
                          {new Date(credential.created).toLocaleDateString()}
                        </div>

                        <div className="flex flex-col space-y-2">
                          {isAuthenticated &&
                          currentWalletAddress === credential.walletAddress ? (
                            <button
                              onClick={handleLogout}
                              className="text-sm bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition font-semibold w-full"
                              title="Log out of this passkey"
                            >
                              Log out PassKey
                            </button>
                          ) : (
                            <button
                              onClick={() =>
                                handleAuthenticateWithWallet(
                                  credential.walletAddress,
                                )
                              }
                              disabled={isAuthenticating}
                              className="text-sm bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed font-semibold w-full"
                              title="Log in with this passkey"
                            >
                              {isAuthenticating
                                ? "Authenticating..."
                                : "Log in with PassKey"}
                            </button>
                          )}

                          {/* Delete button - repositioned for mobile */}
                          <div className="flex justify-center">
                            <button
                              onClick={() => handleDeletePasskey(credential.id)}
                              className="text-lg text-red-500 hover:text-red-700 transition cursor-pointer p-1"
                              title="Delete this passkey"
                            >
                              🗑️
                            </button>
                          </div>
                        </div>
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
          <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
            <p className="text-blue-800 text-sm">{authMessage}</p>
          </div>
        )}

        {authError && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-red-800 text-sm">{authError}</p>
          </div>
        )}

        {/* Registration Section */}
        {isConnected && !hasPasskeys && (
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Register Passkey</h3>
            <p className="text-sm text-gray-600 mb-4">
              Create a passkey to secure your wallet operations. This will use
              your device's biometric authentication or a hardware security key.
            </p>

            <div className="space-y-3">
              <button
                onClick={handleRegister}
                disabled={isRegistering}
                className="w-full bg-green-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-green-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isRegistering ? "Creating Passkey..." : "Create Passkey"}
              </button>
            </div>
          </div>
        )}

        {/* PWA Install Prompt */}
        {showInstallPrompt && !isInstalled && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-2xl shadow-xl max-w-sm w-full p-6">
              <div className="text-center">
                <div className="mb-4">
                  <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <svg
                      className="w-8 h-8 text-blue-600"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 4v16m8-8H4"
                      />
                    </svg>
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    Install Wallet Passkey
                  </h3>
                  <p className="text-sm text-gray-600 mb-4">
                    Install our app for a better experience with offline access
                    and native app features.
                  </p>
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={dismissInstallPrompt}
                    className="flex-1 px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition font-medium"
                  >
                    Not now
                  </button>
                  <button
                    onClick={handleInstallPWA}
                    className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition font-medium"
                  >
                    Install
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
