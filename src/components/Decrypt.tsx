import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { getMasterKeyForOperation } from "../lib/passkeys";

export function Decrypt() {
  const { isAuthenticated, currentWalletAddress } = useAuth();
  const [encryptedMessage, setEncryptedMessage] = useState("");
  const [decryptedMessage, setDecryptedMessage] = useState<string | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptionMode, setDecryptionMode] = useState<"myself" | "someone">(
    "myself",
  );
  const [senderPublicKey, setSenderPublicKey] = useState("");

  const handleDecrypt = async () => {
    if (!encryptedMessage.trim()) {
      alert("Please enter an encrypted message to decrypt");
      return;
    }

    if (!currentWalletAddress) {
      alert("No wallet address available. Please authenticate first.");
      return;
    }

    setIsDecrypting(true);

    try {
      // Get master key for this operation (requires biometric verification)
      const keyResult = await getMasterKeyForOperation(currentWalletAddress);

      if (!keyResult.success || !keyResult.masterKey) {
        alert(keyResult.error || "Failed to get decryption key");
        return;
      }

      let decryptionKey: Uint8Array;

      if (decryptionMode === "myself") {
        // For self-decryption: use master key directly as AES key
        decryptionKey = keyResult.masterKey;
      } else {
        // For peer decryption: derive shared secret using X25519 ECDH
        const { x25519DeriveKeypair, x25519DeriveSharedSecret } =
          await import("../lib/passkeys");

        // Derive our X25519 private key from master key
        const { privateKey: ourPrivateKey } = x25519DeriveKeypair(
          keyResult.masterKey,
        );

        // Decode sender's public key from base64
        const senderPublicKeyBytes = new Uint8Array(
          atob(senderPublicKey)
            .split("")
            .map((c) => c.charCodeAt(0)),
        );

        // Derive shared secret using ECDH
        decryptionKey = await x25519DeriveSharedSecret(
          ourPrivateKey,
          senderPublicKeyBytes,
        );
      }

      // Decode the base64 encrypted message
      const combinedData = new Uint8Array(
        atob(encryptedMessage)
          .split("")
          .map((c) => c.charCodeAt(0)),
      );

      // Extract IV (first 12 bytes) and encrypted data
      const iv = combinedData.slice(0, 12);
      const encryptedData = combinedData.slice(12);

      // Import crypto key using master key
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        decryptionKey.buffer.slice(
          decryptionKey.byteOffset,
          decryptionKey.byteOffset + decryptionKey.byteLength,
        ) as ArrayBuffer,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"],
      );

      // Decrypt the message
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        encryptedData,
      );

      // Convert back to text
      const decryptedText = new TextDecoder().decode(decrypted);
      setDecryptedMessage(decryptedText);
    } catch (error) {
      console.error("Decryption failed:", error);
      alert(
        "Decryption failed. Please check that the encrypted message is valid and you're using the correct account.",
      );
    } finally {
      setIsDecrypting(false);
    }
  };

  const clearForm = () => {
    setEncryptedMessage("");
    setDecryptedMessage(null);
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
              You must authenticate with your passkey to access decryption
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
          Decrypt a Message
        </h2>

        <div className="space-y-6">
          {/* Decryption Mode Toggle */}
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-3">
              Decryption Mode
            </label>
            <div className="flex gap-4">
              <button
                onClick={() => setDecryptionMode("myself")}
                className={`px-4 py-2 rounded-md font-medium transition ${
                  decryptionMode === "myself"
                    ? "bg-slate-900 text-white"
                    : "bg-slate-100 text-slate-700 hover:bg-slate-200"
                }`}
              >
                Decrypt for Myself
              </button>
              <button
                onClick={() => setDecryptionMode("someone")}
                className={`px-4 py-2 rounded-md font-medium transition ${
                  decryptionMode === "someone"
                    ? "bg-slate-900 text-white"
                    : "bg-slate-100 text-slate-700 hover:bg-slate-200"
                }`}
              >
                Decrypt from Someone Else
              </button>
            </div>
          </div>

          {/* Sender Public Key Input (only for "someone" mode) */}
          {decryptionMode === "someone" && (
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-3">
                Sender's Public Key
              </label>
              <input
                type="text"
                value={senderPublicKey}
                onChange={(e) => setSenderPublicKey(e.target.value)}
                placeholder="Enter sender's X25519 public key (base64)"
                className="w-full px-4 py-3 border border-slate-300 rounded-md focus:ring-1 focus:ring-slate-900 focus:border-slate-900 font-mono text-sm"
              />
              <p className="text-xs text-slate-500 mt-1">
                The sender must share their public key with you
              </p>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-3">
              Encrypted Message
            </label>
            <textarea
              value={encryptedMessage}
              onChange={(e) => setEncryptedMessage(e.target.value)}
              placeholder="Paste the encrypted message here..."
              rows={4}
              className="w-full px-4 py-3 border border-slate-300 rounded-md focus:ring-1 focus:ring-slate-900 focus:border-slate-900 resize-none font-mono text-sm"
            />
          </div>

          <button
            onClick={handleDecrypt}
            disabled={
              !encryptedMessage.trim() ||
              isDecrypting ||
              (decryptionMode === "someone" && !senderPublicKey.trim())
            }
            className="w-full bg-slate-900 text-white px-6 py-3 rounded-md font-medium hover:bg-slate-800 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isDecrypting ? "Decrypting..." : "Decrypt Message"}
          </button>

          {decryptedMessage && (
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-3">
                Decrypted Message
              </label>
              <textarea
                value={decryptedMessage}
                readOnly
                rows={6}
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
