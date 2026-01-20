import { useState } from "react";
import { useSignMessage, useAccount } from "wagmi";
import {
  registerPasskey,
  getStoredCredentials,
  deletePasskey,
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

  return (
    <div className="max-w-2xl mx-auto py-12 px-4">
      <div className="bg-white p-8 rounded-2xl shadow-sm border border-gray-100">
        {/* Wallet Section */}
        <div className="mb-6">
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
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Registered Passkeys</h3>
            <div className="space-y-3">
              {getStoredCredentials(address || undefined).map(
                (credential, index) => (
                  <div
                    key={credential.id}
                    className="p-4 border border-gray-200 rounded-lg bg-gray-50"
                  >
                    <div className="grid grid-cols-2 gap-4">
                      {/* Left Column */}
                      <div className="space-y-2">
                        <div className="font-medium text-sm">
                          Passkey #{index + 1}
                        </div>
                        <div className="text-xs text-gray-600">
                          <span className="font-medium">Wallet:</span>{" "}
                          <code className="bg-blue-100 text-blue-800 px-1 py-0.5 rounded text-xs">
                            {credential.walletAddress
                              ? `${credential.walletAddress.slice(
                                  0,
                                  6,
                                )}...${credential.walletAddress.slice(-4)}`
                              : "Legacy passkey"}
                          </code>
                        </div>
                        <div className="text-xs text-gray-600">
                          <span className="font-medium">Credential ID:</span>{" "}
                          <code className="bg-gray-100 px-1 py-0.5 rounded text-xs">
                            {credential.id.substring(0, 20)}...
                          </code>
                        </div>
                        <div className="mt-1">
                          <button
                            onClick={() => handleDeletePasskey(credential.id)}
                            className="text-xl text-red-500 hover:text-red-700 transition cursor-pointer"
                            title="Delete this passkey"
                          >
                            🗑️
                          </button>
                        </div>
                      </div>

                      {/* Right Column */}
                      <div className="flex flex-col items-end justify-around h-full">
                        <div className="text-xs text-gray-500 text-right">
                          Created:{" "}
                          {new Date(credential.created).toLocaleDateString()}
                        </div>

                        <div className="flex flex-col items-end">
                          {isAuthenticated &&
                          currentWalletAddress === credential.walletAddress ? (
                            <button
                              onClick={handleLogout}
                              className="text-base bg-red-600 text-white px-6 py-3 rounded-lg hover:bg-red-700 transition font-semibold"
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
                              className="text-base bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed font-semibold"
                              title="Log in with this passkey"
                            >
                              {isAuthenticating
                                ? "Authenticating..."
                                : "Log in with PassKey"}
                            </button>
                          )}
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
      </div>
    </div>
  );
}
