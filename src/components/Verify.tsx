import { useState } from "react";
import { useAuth } from "../context/AuthContext";

export function Verify() {
  const { isAuthenticated } = useAuth();
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  const [verificationResult, setVerificationResult] = useState<string | null>(
    null,
  );

  const handleVerify = () => {
    if (!message.trim() || !signature.trim()) {
      alert("Please enter both message and signature");
      return;
    }

    // TODO: Implement actual signature verification logic
    // For now, just show a placeholder
    const isValid = Math.random() > 0.5; // Random result for demo
    setVerificationResult(
      isValid ? "Signature is valid" : "Signature is invalid",
    );
  };

  const clearForm = () => {
    setMessage("");
    setSignature("");
    setVerificationResult(null);
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
              You must authenticate with your passkey to access signature
              verification functionality.
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
          Verify a Signature
        </h2>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-3">
              Message
            </label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Enter the original message..."
              rows={6}
              className="w-full px-4 py-3 border border-slate-300 rounded-md focus:ring-1 focus:ring-slate-900 focus:border-slate-900 resize-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-3">
              Signature
            </label>
            <input
              type="text"
              value={signature}
              onChange={(e) => setSignature(e.target.value)}
              placeholder="Enter the signature to verify..."
              className="w-full px-4 py-3 border border-slate-300 rounded-md focus:ring-1 focus:ring-slate-900 focus:border-slate-900"
            />
          </div>

          <button
            onClick={handleVerify}
            disabled={!message.trim() || !signature.trim()}
            className="w-full bg-slate-900 text-white px-6 py-3 rounded-md font-medium hover:bg-slate-800 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Verify Signature
          </button>

          {verificationResult && (
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-3">
                Verification Result
              </label>
              <div
                className={`w-full px-4 py-3 border rounded-md font-medium text-sm ${
                  verificationResult.includes("valid")
                    ? "bg-slate-50 border-slate-200 text-slate-700"
                    : "bg-slate-50 border-slate-200 text-slate-700"
                }`}
              >
                {verificationResult}
              </div>
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
