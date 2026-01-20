import { useEffect, useState } from "react";
import accountCache from "../lib/accountCache";

export function usePrice(
  coingeckoApiUrl: string,
  balanceData: any | null,
  cachedBalance: { formatted: string } | null,
  isConnected: boolean
) {
  const [priceUsd, setPriceUsd] = useState<number | null>(null);
  const [isPriceLoading, setIsPriceLoading] = useState(false);

  useEffect(() => {
    if (!isConnected) return;

    // Proceed if we have either live on-chain balance or a cached balance
    if (!balanceData && !cachedBalance) {
      setPriceUsd(null);
      return;
    }

    let mounted = true;
    async function fetchPrice() {
      setIsPriceLoading(true);
      try {
        const cached = accountCache.readPrice();
        if (cached != null) {
          if (mounted) setPriceUsd(cached);
          if (mounted) setIsPriceLoading(false);
          return;
        }

        const res = await fetch(
          `${coingeckoApiUrl}simple/price?ids=ethereum&vs_currencies=usd`
        );
        if (!res.ok) throw new Error("price fetch failed");
        const json = await res.json();
        const price = json?.ethereum?.usd;
        if (typeof price === "number") {
          if (mounted) setPriceUsd(price);
          accountCache.writePrice(price);
        } else {
          if (mounted) setPriceUsd(null);
        }
      } catch (e) {
        if (mounted) setPriceUsd(null);
      } finally {
        if (mounted) setIsPriceLoading(false);
      }
    }

    fetchPrice();
    return () => {
      mounted = false;
    };
  }, [coingeckoApiUrl, balanceData, cachedBalance, isConnected]);

  return { priceUsd, isPriceLoading };
}

export default usePrice;
