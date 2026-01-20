# 🔐 Wallet Passkey - Enterprise Web3 Authentication

A revolutionary Web3 wallet application featuring **hardware-backed passkey authentication** with **enterprise-grade cryptography**. Combines Web3 wallet ownership verification with biometric security for the ultimate in secure, user-friendly authentication.

## 🌟 **Key Features**

- 🔐 **Hardware-Backed Security**: WebAuthn passkeys with Touch ID, Face ID, and security keys
- 🔑 **Wallet Ownership Verification**: Cryptographic proof of wallet control
- 🛡️ **Enterprise Cryptography**: HKDF key derivation + AES-GCM encryption
- ⚡ **Zero-Knowledge Architecture**: Sensitive keys never stored in plaintext
- 🎯 **Biometric UX**: Hardware authentication without passwords
- 🚀 **Production Ready**: Built with modern Web3 and crypto standards

## 🔐 **How Wallet Signature → Passkey Encryption Works**

This application implements a **5-phase cryptographic architecture** that combines Web3 wallet ownership with hardware-backed passkey security:

### **Phase 1: Wallet Bootstrap** 🔑

```
User clicks "Create Passkey" → Wallet signature prompt appears
```

- User signs a comprehensive challenge message with their connected wallet
- Challenge includes domain verification and security warnings
- Proves wallet ownership before creating passkey credentials

### **Phase 2: Master Key Derivation** 🛠️

```
walletSignature → HKDF(walletSignature, salt, info) → masterKey
```

- Uses **HKDF (HMAC-based Key Derivation Function)** with SHA-256
- Salt: App version (`"your-app-v1"`)
- Info: User address + chain ID for deterministic derivation
- Produces 32-byte cryptographically secure master key

### **Phase 3: WebAuthn Passkey Creation** 🔐

```
masterKey exists → Create WebAuthn credential
```

- Hardware-backed passkey using WebAuthn API
- Supports Touch ID, Face ID, Windows Hello, and security keys
- User verification required (biometric/PIN)
- Creates phishing-resistant credential

### **Phase 4: Key Wrapping** 📦

```
masterKey → AES-GCM(passkeySignature) → wrappedKey + IV
```

- **AES-GCM (Galois/Counter Mode)** authenticated encryption
- Wrapping key derived from passkey signature via HKDF
- Generates cryptographically secure 12-byte IV
- Stores wrapped master key securely

### **Phase 5: Biometric Usage** 🎯

```
Passkey auth → Unwrap masterKey → Use for operations
```

- User authenticates with biometric/passkey
- Unwraps master key using AES-GCM decryption
- Zero-knowledge: master key exists only in memory
- Automatic cleanup after operations complete

## 🏗️ **Architecture Benefits**

### **Security Properties**

- **🔐 End-to-End Encryption**: Master keys encrypted with AES-GCM
- **🔑 Deterministic Derivation**: Same wallet → same keys (recoverable)
- **🛡️ Hardware Security**: TPM/TEE-backed key operations
- **🚫 Anti-Phishing**: Domain verification in challenges
- **⚡ Zero Trust**: No sensitive data in browser storage

### **User Experience**

- **👆 One-Touch Authentication**: Biometric hardware UX
- **🔄 Wallet Integration**: Seamlessly connects to existing wallets
- **📱 Cross-Device**: iCloud/Google sync for passkeys
- **🚀 Fast Operations**: Hardware-accelerated cryptography
- **🔒 Passwordless**: No passwords to remember or type

### **Technical Advantages**

- **🏢 Enterprise Grade**: FIPS-compliant algorithms
- **🌐 Web Standards**: WebAuthn + Web Crypto API
- **📊 Auditable**: Complete cryptographic operation trail
- **🔧 Extensible**: Exported functions for additional features
- **⚡ Performant**: Browser-native cryptographic acceleration

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
