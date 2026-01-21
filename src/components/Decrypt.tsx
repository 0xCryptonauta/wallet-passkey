import { useState } from "react";
import { useAuth } from "../context/AuthContext";

export function Decrypt() {
  const { isAuthenticated, masterKey } = useAuth();
  const [encryptedMessage, setEncryptedMessage] = useState("");
  const [decryptedMessage, setDecryptedMessage] = useState<string | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);

  const handleDecrypt = async () => {
    if (!encryptedMessage.trim()) {
      alert("Please enter an encrypted message to decrypt");
      return;
    }

    if (!masterKey) {
      alert("No decryption key available. Please authenticate first.");
      return;
    }

    setIsDecrypting(true);

    try {
      // Decode the base64 encrypted message
      const combinedData = new Uint8Array(
        atob(encryptedMessage)
          .split("")
          .map((c) => c.charCodeAt(0)),
      );

      // Extract IV (first 12 bytes) and encrypted data
      const iv = combinedData.slice(0, 12);
      const encryptedData = combinedData.slice(12);

      // Import crypto key
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        masterKey.buffer.slice(
          masterKey.byteOffset,
          masterKey.byteOffset + masterKey.byteLength,
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
        <div className="bg-white p-8 rounded-2xl shadow-sm border border-gray-100">
          <div className="text-center">
            <div className="mb-4">
              <svg
                className="mx-auto h-12 w-12 text-gray-400"
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
            <h2 className="text-2xl font-bold mb-4">Authentication Required</h2>
            <p className="text-gray-600 mb-6">
              You must authenticate with your passkey to access decryption
              functionality.
            </p>
            <p className="text-sm text-gray-500">
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
      <div className="bg-white p-8 rounded-2xl shadow-sm border border-gray-100">
        <h2 className="text-2xl font-bold mb-6">Decrypt a Message</h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Encrypted Message
            </label>
            <textarea
              value={encryptedMessage}
              onChange={(e) => setEncryptedMessage(e.target.value)}
              placeholder="Paste the encrypted message here..."
              rows={4}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none font-mono text-sm"
            />
          </div>

          <button
            onClick={handleDecrypt}
            disabled={!encryptedMessage.trim() || isDecrypting}
            className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isDecrypting ? "Decrypting..." : "Decrypt Message"}
          </button>

          {decryptedMessage && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Decrypted Message
              </label>
              <textarea
                value={decryptedMessage}
                readOnly
                rows={6}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg bg-gray-50 text-gray-600 font-mono text-sm cursor-not-allowed resize-none"
              />
              <button
                onClick={clearForm}
                className="mt-3 w-full bg-gray-300 text-gray-800 px-6 py-2 rounded-lg font-semibold hover:bg-gray-400 transition"
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
