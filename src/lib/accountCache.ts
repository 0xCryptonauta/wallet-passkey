const ENS_CACHE_KEY = "ensCache";
const ENS_CACHE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 1 week
const PRICE_CACHE_KEY = "priceCache";
const PRICE_CACHE_EXPIRY_MS = 60 * 60 * 1000; // 1 hour
const BALANCE_CACHE_KEY = "balanceCache";
const BALANCE_CACHE_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

export interface EnsCacheEntry {
  ensName: string | null;
  timestamp: number;
}

export interface PriceCacheEntry {
  price: number;
  timestamp: number;
}

export interface BalanceCacheEntry {
  formatted: string;
  symbol: string | null;
  timestamp: number;
}

function keyFor(k: string, address?: string) {
  return address ? `${k}:${address.toLowerCase()}` : k;
}

export function readEns(address?: string): string | null {
  if (!address || typeof window === "undefined") return null;
  try {
    const cached = localStorage.getItem(keyFor(ENS_CACHE_KEY, address));
    if (!cached) return null;
    const parsed: EnsCacheEntry = JSON.parse(cached);
    const isExpired = Date.now() - parsed.timestamp > ENS_CACHE_EXPIRY_MS;
    if (isExpired) {
      localStorage.removeItem(keyFor(ENS_CACHE_KEY, address));
      return null;
    }
    return parsed.ensName;
  } catch (e) {
    console.warn("readEns failed", e);
    return null;
  }
}

export function writeEns(address: string, ensName: string | null) {
  if (!address || typeof window === "undefined") return;
  const entry: EnsCacheEntry = { ensName, timestamp: Date.now() };
  try {
    localStorage.setItem(keyFor(ENS_CACHE_KEY, address), JSON.stringify(entry));
  } catch (e) {
    console.warn("writeEns failed", e);
  }
}

export function readBalance(address?: string): BalanceCacheEntry | null {
  if (!address || typeof window === "undefined") return null;
  try {
    const cached = localStorage.getItem(keyFor(BALANCE_CACHE_KEY, address));
    if (!cached) return null;
    const parsed: BalanceCacheEntry = JSON.parse(cached);
    const isExpired = Date.now() - parsed.timestamp > BALANCE_CACHE_EXPIRY_MS;
    if (isExpired) {
      localStorage.removeItem(keyFor(BALANCE_CACHE_KEY, address));
      return null;
    }
    return parsed;
  } catch (e) {
    console.warn("readBalance failed", e);
    return null;
  }
}

export function writeBalance(address: string, entry: BalanceCacheEntry) {
  if (!address || typeof window === "undefined") return;
  try {
    localStorage.setItem(
      keyFor(BALANCE_CACHE_KEY, address),
      JSON.stringify(entry)
    );
  } catch (e) {
    console.warn("writeBalance failed", e);
  }
}

export function readPrice(): number | null {
  if (typeof window === "undefined") return null;
  try {
    const cached = localStorage.getItem(PRICE_CACHE_KEY);
    if (!cached) return null;
    const parsed: PriceCacheEntry = JSON.parse(cached);
    const isExpired = Date.now() - parsed.timestamp > PRICE_CACHE_EXPIRY_MS;
    if (isExpired) {
      localStorage.removeItem(PRICE_CACHE_KEY);
      return null;
    }
    return parsed.price;
  } catch (e) {
    console.warn("readPrice failed", e);
    return null;
  }
}

export function writePrice(price: number) {
  if (typeof window === "undefined") return;
  try {
    const entry: PriceCacheEntry = { price, timestamp: Date.now() };
    localStorage.setItem(PRICE_CACHE_KEY, JSON.stringify(entry));
  } catch (e) {
    console.warn("writePrice failed", e);
  }
}

export default {
  readEns,
  writeEns,
  readBalance,
  writeBalance,
  readPrice,
  writePrice,
};
