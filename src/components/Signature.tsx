import { useState } from "react";
import { useSignMessage } from "wagmi";

export function Signature() {
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
      }
    );
  };

  return (
    <div className="max-w-2xl mx-auto py-12 px-4">
      <div className="bg-white p-8 rounded-2xl shadow-sm border border-gray-100">
        <h2 className="text-2xl font-bold mb-6">Sign a Message</h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Message to Sign
            </label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Enter the message you want to sign..."
              disabled={!!signature}
              rows={6}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:bg-gray-100 disabled:cursor-not-allowed resize-none"
            />
          </div>

          <button
            onClick={handleSign}
            disabled={isPending || !!signature || !message.trim()}
            className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isPending ? "Signing..." : "Sign Message"}
          </button>

          {signature && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Signature
              </label>
              <input
                type="text"
                value={signature}
                readOnly
                className="w-full px-4 py-3 border border-gray-300 rounded-lg bg-gray-50 text-gray-600 font-mono text-sm cursor-not-allowed"
              />
              <button
                onClick={() => {
                  setSignature(null);
                  setMessage("");
                }}
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
