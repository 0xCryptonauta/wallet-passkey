import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { VitePWA } from "vite-plugin-pwa";

// https://vitejs.dev/config/
export default defineConfig({
  base: "/",
  plugins: [
    react(),
    tailwindcss(), // Add this line
    VitePWA({
      registerType: "autoUpdate",
      workbox: {
        globPatterns: ["**/*.{js,css,html,ico,png,svg}"],
        runtimeCaching: [
          {
            urlPattern: /^https:\/\/.*\.jsdelivr\.net\/.*/i,
            handler: "CacheFirst",
            options: {
              cacheName: "cdn-cache",
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 60 * 60 * 24 * 365, // <== 365 days
              },
            },
          },
        ],
      },
      manifest: {
        name: "Wallet Passkey",
        short_name: "WalletPK",
        description: "A wallet application with passkey authentication",
        theme_color: "#ffffff",
        icons: [
          {
            src: "IB_icon.png",
            sizes: "192x192",
            type: "image/png",
          },
          {
            src: "IB_icon.png",
            sizes: "512x512",
            type: "image/png",
          },
        ],
      },
    }),
  ],
  server: {
    host: true, // Allows access from network interfaces (WiFi, Ethernet, etc.)
  },
});
