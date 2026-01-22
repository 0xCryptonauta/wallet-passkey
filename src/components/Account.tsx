import { useEffect, useState, useMemo } from "react";
import {
  useAccount,
  useConnect,
  useDisconnect,
  useBalance,
  useEnsName,
} from "wagmi";
import { formatUnits } from "viem";
import { useSettings } from "../context/SettingsContext";
// Import your cache helpers
import cache from "../lib/accountCache";

export function Account() {
  const { address, isConnected } = useAccount();
  const { connectors, connect } = useConnect();
  const { disconnect } = useDisconnect();
  const { coingeckoApiUrl } = useSettings();

  const [priceUsd, setPriceUsd] = useState<number | null>(cache.readPrice());

  // 1. ENS Logic: Only fetch if cache is empty
  const initialEns = cache.readEns(address);
  const { data: ensNameData } = useEnsName({
    address,
    chainId: 1,
    query: { enabled: !!address && !initialEns },
  });

  // 2. Balance Logic: Only fetch if cache is empty
  const initialBal = cache.readBalance(address);
  const { data: balanceData } = useBalance({
    address: address || undefined,
    query: { enabled: !!address && !initialBal },
  });

  // 3. Sync Hooks to Cache
  useEffect(() => {
    if (address && ensNameData) cache.writeEns(address, ensNameData);
  }, [ensNameData, address]);

  useEffect(() => {
    if (address && balanceData) {
      cache.writeBalance(address, {
        formatted: Number(
          formatUnits(balanceData.value, balanceData.decimals),
        ).toFixed(6),
        symbol: balanceData.symbol ?? null,
        timestamp: Date.now(),
      });
    }
  }, [balanceData, address]);

  // 4. Price Fetching (respecting readPrice)
  useEffect(() => {
    if (!isConnected || priceUsd) return;

    async function fetchPrice() {
      try {
        const res = await fetch(
          `${coingeckoApiUrl}simple/price?ids=ethereum&vs_currencies=usd`,
        );
        const json = await res.json();
        const price = json?.ethereum?.usd;
        if (price) {
          setPriceUsd(price);
          cache.writePrice(price);
        }
      } catch (e) {
        console.error(e);
      }
    }
    fetchPrice();
  }, [isConnected, coingeckoApiUrl, priceUsd]);

  // 5. Limited Connectors List (Max 6 for debugging)
  const limitedConnectors = useMemo(() => connectors.slice(0, 6), [connectors]);

  // Known wallet icons - override icons for injected connectors
  const walletIcons: Record<string, string> = {
    MetaMask: "/MetaMask-icon.svg",
    WalletConnect: "/walletConnect_icon.svg",
  };

  const getWalletIcon = (connector: any) => {
    // Prioritize custom icons from walletIcons over connector.icon
    if (walletIcons[connector.name]) {
      return walletIcons[connector.name];
    }
    // If connector named "Injected" has no icon, use MetaMask icon
    if (connector.name === "Injected" && !connector.icon) {
      return "/MetaMask-icon.svg";
    }
    return connector.icon;
  };

  if (isConnected) {
    // Priority: Live Data -> Cached Data -> Fallback
    const displayBal = balanceData
      ? Number(formatUnits(balanceData.value, balanceData.decimals)).toFixed(6)
      : initialBal?.formatted || "0.000000";

    const displayEns =
      ensNameData ||
      initialEns ||
      `${address?.slice(0, 6)}...${address?.slice(-4)}`;
    const symbol = balanceData?.symbol || initialBal?.symbol || "";
    const usdValue = (Number(displayBal) * (priceUsd || 0)).toFixed(2);

    return (
      <div className="flex items-center justify-end gap-4">
        <div className="text-right">
          <div className="text-sm font-bold">
            {displayBal} {symbol}
          </div>
          {priceUsd && (
            <div className="text-xs text-gray-500">${usdValue} USD</div>
          )}
          <div className="text-xs font-mono text-slate-600">{displayEns}</div>
        </div>
        <button
          onClick={() => disconnect()}
          className="text-xs bg-gray-200 p-2 rounded cursor-pointer hover:bg-gray-300 transition"
        >
          Disconnect
        </button>
      </div>
    );
  }

  return (
    <div className="flex justify-end gap-2">
      {limitedConnectors.map((c) => (
        <button
          key={c.uid}
          onClick={async () => {
            try {
              await connect({ connector: c });
            } catch (error) {
              console.error(`Failed to connect to ${c.name}:`, error);
            }
          }}
          className="w-12 h-12 bg-white rounded-lg cursor-pointer hover:bg-gray-50 transition flex items-center justify-center"
          title={`Connect with ${c.name}`}
        >
          {getWalletIcon(c) ? (
            <img
              src={getWalletIcon(c)}
              alt={c.name}
              className="w-8 h-8 object-contain"
            />
          ) : (
            <span className="text-xs font-medium text-gray-700">
              {c.name.charAt(0).toUpperCase()}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}
