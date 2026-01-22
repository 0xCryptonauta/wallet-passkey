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
          className="bg-slate-900 text-white px-4 py-2 rounded-md hover:bg-slate-800 transition"
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
      <span className="text-sm text-slate-600">
        {balance.display} {balance.symbol} {balance.usd && `($${balance.usd})`}
      </span>
      <span className="text-sm font-mono bg-slate-100 p-2 rounded">
        {ensName}
      </span>
      <button
        onClick={() => disconnect()}
        className="bg-slate-900 text-white px-4 py-2 rounded-md hover:bg-slate-800 transition"
      >
        Disconnect
      </button>
    </div>
  );
};
