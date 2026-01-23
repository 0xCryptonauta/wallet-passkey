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
      setAuthError(null);
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
    <div className="max-w-2xl mx-auto py-2 px-4">
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
                            className="px-4 py-2 text-sm bg-green-600 text-white rounded-md hover:bg-green-700 transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer font-medium"
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

                    {/* X25519 Public Key Display */}
                    {credential.x25519PublicKey && (
                      <div className="mt-3 pt-3 border-t border-slate-200">
                        <div className="flex items-center justify-between">
                          <div className="flex-1">
                            <div className="text-xs text-slate-500 mb-1">
                              X25519 Public Key (for peer messaging)
                            </div>
                            <div className="text-xs text-slate-600 font-mono bg-slate-50 p-2 rounded break-all">
                              {credential.x25519PublicKey}
                            </div>
                          </div>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(
                                credential.x25519PublicKey || "",
                              );
                              setAuthMessage("Public key copied to clipboard!");
                              setTimeout(() => setAuthMessage(null), 2000);
                            }}
                            className="ml-3 p-2 text-slate-500 hover:text-slate-700 transition cursor-pointer"
                            title="Copy public key"
                          >
                            <svg
                              className="w-4 h-4"
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                              />
                            </svg>
                          </button>
                        </div>
                      </div>
                    )}
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

export default PasskeyAuth;
