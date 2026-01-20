import React from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { WagmiProvider, type Config } from "wagmi";
import { createWagmiConfig } from "./wagmi";
import { SettingsProvider } from "./context/SettingsContext";
import { AuthProvider } from "./context/AuthContext";
import "./index.css";
import App from "./App.tsx";

const queryClient = new QueryClient();
const SETTINGS_CACHE_KEY = "initSettingsCache";
const SETTINGS_CACHE_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000; // 1 month

// Create config ONCE at module load time with empty RPC urls (will use defaults)
const config: Config = createWagmiConfig([]);

interface SettingsCacheEntry {
  rpcUrls: string[];
  coingeckoApiUrl: string;
  timestamp: number;
}

async function bootstrap() {
  let coingeckoApiUrl = "";

  // Load settings from cache or fetch
  const cached = localStorage.getItem(SETTINGS_CACHE_KEY);
  if (cached) {
    try {
      const parsed: SettingsCacheEntry = JSON.parse(cached);
      const isExpired =
        Date.now() - parsed.timestamp > SETTINGS_CACHE_EXPIRY_MS;

      if (!isExpired) {
        coingeckoApiUrl = parsed.coingeckoApiUrl;
        console.log("Using cached initSettings");
      } else {
        localStorage.removeItem(SETTINGS_CACHE_KEY);
      }
    } catch (e) {
      console.warn("Failed to parse settings cache", e);
    }
  }

  // If no valid cache, fetch fresh settings
  if (!coingeckoApiUrl) {
    try {
      const res = await fetch("/initSettings.json");
      if (res.ok) {
        const json = await res.json();
        if (typeof json.COINGECKO_URL === "string")
          coingeckoApiUrl = json.COINGECKO_URL;

        // Cache the settings
        const cacheEntry: SettingsCacheEntry = {
          rpcUrls: [],
          coingeckoApiUrl,
          timestamp: Date.now(),
        };
        localStorage.setItem(SETTINGS_CACHE_KEY, JSON.stringify(cacheEntry));
      } else {
        console.warn("Could not load /initSettings.json, using defaults");
      }
    } catch (e) {
      console.warn("Failed to fetch /initSettings.json", e);
    }
  }

  console.log("Rendering app with config created at module load");

  createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <WagmiProvider config={config}>
        <QueryClientProvider client={queryClient}>
          <SettingsProvider settings={{ coingeckoApiUrl }}>
            <AuthProvider>
              <App />
            </AuthProvider>
          </SettingsProvider>
        </QueryClientProvider>
      </WagmiProvider>
    </React.StrictMode>
  );
}

bootstrap();
