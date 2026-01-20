// src/components/AccountUI.tsx
import { useConnect, useDisconnect } from "wagmi";

export const ConnectorsList = () => {
  const { connectors, connect } = useConnect();
  return (
    <div className="flex gap-2">
      {connectors.map((c) => (
        <button
          key={c.uid}
          onClick={() => connect({ connector: c })}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition"
        >
          Connect {c.name}
        </button>
      ))}
    </div>
  );
};

export const AccountInfo = ({
  balance,
  ensName,
}: {
  balance: any;
  ensName: string;
}) => {
  const { disconnect } = useDisconnect();
  return (
    <div className="flex items-center gap-4">
      <span className="text-sm text-gray-600">
        {balance.display} {balance.symbol} {balance.usd && `($${balance.usd})`}
      </span>
      <span className="text-sm font-mono bg-gray-100 p-2 rounded">
        {ensName}
      </span>
      <button
        onClick={() => disconnect()}
        className="bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600 transition"
      >
        Disconnect
      </button>
    </div>
  );
};
