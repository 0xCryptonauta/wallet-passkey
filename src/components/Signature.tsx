import { useState } from "react";
import { useSignMessage } from "wagmi";
import { useAuth } from "../context/AuthContext";

export function Signature() {
  const { isAuthenticated } = useAuth();
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState<string | null>(null);
  const { signMessage, isPending } = useSignMessage();

  const handleSign = async () => {
    if (!message.trim()) {
      alert("Please enter a message to sign");
      return;
    }

    signMessage(
      { message },
      {
        onSuccess(data) {
          setSignature(data);
        },
        onError(error) {
          console.error("Signature error:", error);
          alert("Failed to sign message");
        },
      },
    );
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
              You must authenticate with your passkey to access message signing
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
          Sign a Message
        </h2>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-3">
              Message to Sign
            </label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Enter the message you want to sign..."
              disabled={!!signature}
              rows={6}
              className="w-full px-4 py-3 border border-slate-300 rounded-md focus:ring-1 focus:ring-slate-900 focus:border-slate-900 disabled:bg-slate-50 disabled:cursor-not-allowed resize-none"
            />
          </div>

          <button
            onClick={handleSign}
            disabled={isPending || !!signature || !message.trim()}
            className="w-full bg-slate-900 text-white px-6 py-3 rounded-md font-medium hover:bg-slate-800 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isPending ? "Signing..." : "Sign Message"}
          </button>

          {signature && (
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-3">
                Signature
              </label>
              <input
                type="text"
                value={signature}
                readOnly
                className="w-full px-4 py-3 border border-slate-300 rounded-md bg-slate-50 text-slate-600 font-mono text-sm cursor-not-allowed"
              />
              <button
                onClick={() => {
                  setSignature(null);
                  setMessage("");
                }}
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
