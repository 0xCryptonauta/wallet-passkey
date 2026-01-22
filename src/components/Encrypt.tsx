import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { getMasterKeyForOperation } from "../lib/passkeys";

export function Encrypt() {
  const { isAuthenticated, currentWalletAddress } = useAuth();
  const [message, setMessage] = useState("");
  const [encryptedMessage, setEncryptedMessage] = useState<string | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);

  const handleEncrypt = async () => {
    if (!message.trim()) {
      alert("Please enter a message to encrypt");
      return;
    }

    if (!currentWalletAddress) {
      alert("No wallet address available. Please authenticate first.");
      return;
    }

    setIsEncrypting(true);

    try {
      // Get master key for this operation (requires biometric verification)
      const keyResult = await getMasterKeyForOperation(currentWalletAddress);

      if (!keyResult.success || !keyResult.masterKey) {
        alert(keyResult.error || "Failed to get encryption key");
        return;
      }

      // Import crypto functions
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyResult.masterKey.buffer.slice(
          keyResult.masterKey.byteOffset,
          keyResult.masterKey.byteOffset + keyResult.masterKey.byteLength,
        ) as ArrayBuffer,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"],
      );

      // Generate a random IV for each encryption
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // Encrypt the message
      const encodedMessage = new TextEncoder().encode(message);
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        encodedMessage,
      );

      // Combine IV and encrypted data, base64 encode
      const combined = new Uint8Array(iv.length + encrypted.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(encrypted), iv.length);

      setEncryptedMessage(btoa(String.fromCharCode(...combined)));
    } catch (error) {
      console.error("Encryption failed:", error);
      alert("Encryption failed. Please try again.");
    } finally {
      setIsEncrypting(false);
    }
  };

  const clearForm = () => {
    setMessage("");
    setEncryptedMessage(null);
  };

  if (!isAuthenticated) {
    return (
      <div className="max-w-2xl mx-auto py-12 px-4">
        <div className="bg-white p-8 rounded-lg border border-slate-200">
          <div className="text-center">
            <div className="mb-4">
              <svg
                className="mx-auto h-12 w-12 text-slate-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                />
              </svg>
            </div>
            <h2 className="text-xl font-semibold mb-4 text-slate-900">
              Authentication Required
            </h2>
            <p className="text-slate-600 mb-6">
              You must authenticate with your passkey to access encryption
              functionality.
            </p>
            <p className="text-sm text-slate-500">
              Go to the <strong>Auth</strong> tab to register or authenticate
              with your passkey.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto py-12 px-4">
      <div className="bg-white p-8 rounded-lg border border-slate-200">
        <h2 className="text-xl font-semibold mb-6 text-slate-900">
          Encrypt a Message
        </h2>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-3">
              Message to Encrypt
            </label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Enter the message you want to encrypt..."
              rows={6}
              className="w-full px-4 py-3 border border-slate-300 rounded-md focus:ring-1 focus:ring-slate-900 focus:border-slate-900 resize-none"
            />
          </div>

          <button
            onClick={handleEncrypt}
            disabled={!message.trim() || isEncrypting}
            className="w-full bg-slate-900 text-white px-6 py-3 rounded-md font-medium hover:bg-slate-800 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isEncrypting ? "Encrypting..." : "Encrypt Message"}
          </button>

          {encryptedMessage && (
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-3">
                Encrypted Message
              </label>
              <textarea
                value={encryptedMessage}
                readOnly
                rows={4}
                className="w-full px-4 py-3 border border-slate-300 rounded-md bg-slate-50 text-slate-600 font-mono text-sm cursor-not-allowed resize-none"
              />
              <button
                onClick={clearForm}
                className="mt-4 w-full bg-slate-100 text-slate-700 px-6 py-2 rounded-md font-medium hover:bg-slate-200 transition"
              >
                Clear
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
