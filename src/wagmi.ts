// src/wagmi.ts
import { http, createConfig, type Config } from "wagmi";
import { arbitrum, mainnet } from "wagmi/chains";
import { injected, walletConnect, metaMask } from "wagmi/connectors";

// Extend window interface for ethereum
declare global {
  interface Window {
    ethereum?: any;
  }
}

/**
 * Build a wagmi `Config` using an array (pool) of RPC URLs.
 */
export function createWagmiConfig(rpcUrls: string[] = []): Config {
  const rpc =
    Array.isArray(rpcUrls) && rpcUrls.length > 0
      ? rpcUrls[Math.floor(Math.random() * rpcUrls.length)]
      : undefined;

  const projectId =
    import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || "demo-project-id";
  console.log("WalletConnect projectId:", projectId);

  // Check if MetaMask is available and create connectors accordingly
  const connectors = [];

  // Check if MetaMask is available
  const isMetaMaskAvailable =
    typeof window !== "undefined" &&
    window.ethereum &&
    window.ethereum.isMetaMask;

  if (isMetaMaskAvailable) {
    connectors.push(metaMask());
    console.log("Using MetaMask connector");
  } else {
    connectors.push(injected());
    console.log("Using injected connector (MetaMask not available)");
  }

  // Always add WalletConnect
  connectors.push(
    walletConnect({
      projectId,
      showQrModal: true,
    }),
  );

  const config = createConfig({
    chains: [arbitrum, mainnet],
    connectors,
    transports: {
      [arbitrum.id]: rpc ? http(rpc) : http(),
      [mainnet.id]: http(),
    },
    // Global query settings to respect caching and reduce RPC noise
    // This stops the constant calls to Multicall3 on every reload.
    syncConnectedChain: true,
  });

  console.log(
    "Created wagmi config with connectors:",
    config.connectors?.map((c) => c.name),
  );
  return config;
}
