import { useState } from "react";
import { useSignMessage } from "wagmi";
import {
  registerPasskey,
  getStoredCredentials,
  deletePasskey,
} from "../lib/passkeys";
import type { AuthenticationResult } from "../lib/passkeys";
import { useAuth } from "../context/AuthContext";

export function PasskeyAuth() {
  const {
    isAuthenticated,
    isAuthenticating,
    hasPasskeys,
    authenticate,
    logout,
  } = useAuth();
  const { signMessageAsync } = useSignMessage();
  const [isRegistering, setIsRegistering] = useState(false);
  const [authMessage, setAuthMessage] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0); // Force re-render when passkeys change

  const handleRegister = async () => {
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
        walletSignMessage
      );

      if (result.success) {
        setAuthMessage(
          "Passkey created successfully! You can now authenticate."
        );
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

  const handleAuthenticate = async () => {
    setAuthError(null);
    setAuthMessage("Authenticating...");

    const result = await authenticate();

    if (result.success) {
      setAuthMessage("Authentication successful!");
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
        "Are you sure you want to delete this passkey? This action cannot be undone."
      )
    ) {
      const success = deletePasskey(credentialId);
      if (success) {
        setAuthMessage("Passkey deleted successfully");
        setRefreshTrigger((prev) => prev + 1); // Force re-render
        setTimeout(() => setAuthMessage(null), 2000);
      } else {
        setAuthError("Failed to delete passkey");
      }
    }
  };

  return (
    <div className="max-w-2xl mx-auto py-12 px-4">
      <div className="bg-white p-8 rounded-2xl shadow-sm border border-gray-100">
        <h2 className="text-2xl font-bold mb-6">Passkey Authentication</h2>

        {/* Status Section */}
        <div className="mb-6 p-4 bg-gray-50 rounded-lg">
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
              {getStoredCredentials().map((credential, index) => (
                <div
                  key={`${credential.id}-${refreshTrigger}`}
                  className="p-4 border border-gray-200 rounded-lg bg-gray-50"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-sm">
                      Passkey #{index + 1}
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-500">
                        Created:{" "}
                        {new Date(credential.created).toLocaleDateString()}
                      </span>
                      <button
                        onClick={() => handleDeletePasskey(credential.id)}
                        className="text-xs bg-red-500 text-white px-2 py-1 rounded hover:bg-red-600 transition cursor-pointer"
                        title="Delete this passkey"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                  <div className="space-y-1 text-xs text-gray-600">
                    <div>
                      <span className="font-medium">Credential ID:</span>{" "}
                      <code className="bg-gray-100 px-1 py-0.5 rounded text-xs">
                        {credential.id.substring(0, 20)}...
                      </code>
                    </div>
                    <div>
                      <span className="font-medium">Counter:</span>{" "}
                      {credential.counter}
                    </div>
                  </div>
                </div>
              ))}
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
        {!hasPasskeys && (
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

        {/* Authentication Section */}
        {hasPasskeys && !isAuthenticated && (
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Authenticate</h3>
            <p className="text-sm text-gray-600 mb-4">
              Use your passkey to authenticate and access secure wallet
              operations.
            </p>

            <button
              onClick={handleAuthenticate}
              disabled={isAuthenticating}
              className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isAuthenticating
                ? "Authenticating..."
                : "Authenticate with Passkey"}
            </button>
          </div>
        )}

        {/* Logout Section */}
        {isAuthenticated && (
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3">Session Active</h3>
            <p className="text-sm text-gray-600 mb-4">
              You are currently authenticated. You can now access secure wallet
              operations.
            </p>

            <button
              onClick={handleLogout}
              className="w-full bg-gray-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-gray-700 transition"
            >
              Logout
            </button>
          </div>
        )}

        {/* Info Section */}
        <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
          <h4 className="font-semibold text-yellow-800 mb-2">About Passkeys</h4>
          <ul className="text-sm text-yellow-700 space-y-1">
            <li>
              • Passkeys use hardware-backed security for phishing-resistant
              authentication
            </li>
            <li>
              • They work with Touch ID, Face ID, Windows Hello, or hardware
              security keys
            </li>
            <li>
              • No passwords needed - authentication happens directly on your
              device
            </li>
            <li>• Credentials are stored securely and cannot be exported</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
