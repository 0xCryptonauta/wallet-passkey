# ⚡️ Bun + React + Wagmi dApp

A high-performance Web3 application built with **Bun**, **React**, **TypeScript**, and **Tailwind CSS v4**.

## 🛠 Tech Stack

- **Runtime:** [Bun](https://bun.sh/)
- **Frontend:** [React](https://react.dev/) + [Vite](https://vitejs.dev/)
- **Web3:** [Wagmi v3](https://wagmi.sh/) + [Viem](https://viem.sh/)
- **State Management:** [TanStack Query v5](https://tanstack.com/query)
- **Styling:** [Tailwind CSS v4](https://tailwindcss.com/)

## 🚀 Getting Started

### 1. Install Dependencies

```bash
bun install
```

### 2. Run Development Server

```bash
bun dev
```

### 3. Build for Production

```bash
bun run build
```

## 🔌 Configuration

### Wagmi Setup (`src/wagmi.ts`)

```typescript
import { http, createConfig } from "wagmi";
import { mainnet, sepolia } from "wagmi/chains";
import { injected } from "wagmi/connectors";

export const config = createConfig({
  chains: [mainnet, sepolia],
  connectors: [injected()],
  transports: {
    [mainnet.id]: http(),
    [sepolia.id]: http(),
  },
});
```

### Tailwind v4 Setup (`vite.config.ts`)

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
});
```

## 📝 Common Commands

| Command         | Action                                            |
| --------------- | ------------------------------------------------- |
| `bun dev`       | Starts local development server                   |
| `bun run build` | Compiles optimized production build               |
| `bun add <pkg>` | Adds a dependency using Bun's high-speed resolver |
| `bun test`      | Runs the internal Bun test runner                 |

---

Built with ⚡️

```

```
