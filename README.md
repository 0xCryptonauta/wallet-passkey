# 🔐 Wallet Passkey - Enterprise Web3 Authentication

A revolutionary Web3 wallet application featuring **hardware-backed passkey authentication** with **enterprise-grade cryptography**. Combines Web3 wallet ownership verification with biometric security for the ultimate in secure, user-friendly authentication.

## 🌟 **Key Features**

- 🔐 **Hardware-Backed Security**: WebAuthn passkeys with Touch ID, Face ID, and security keys
- 🔑 **Wallet Ownership Verification**: Cryptographic proof of wallet control
- 🔒 **End-to-End Encryption**: Deterministic AES-GCM encryption with passkey-derived keys
- 🔄 **Cross-Device Compatibility**: Same encryption keys work across all devices
- **Wallet-Specific Binding**: Passkeys are cryptographically tied to wallet addresses
- 🛡️ **Enterprise Cryptography**: HKDF key derivation + AES-GCM encryption
- ⚡ **Zero-Knowledge Architecture**: Sensitive keys never stored in plaintext
- 🎯 **Biometric UX**: Hardware authentication without passwords
- 🚀 **Production Ready**: Built with modern Web3 and crypto standards

## 🔐 **Authentication Flow & Session Management**

### **Hybrid Authentication System**

The application implements **intelligent device-aware authentication** that automatically selects the best method for each device:

#### **Device Detection & Method Selection**

```typescript
// Automatically detects device capabilities
const capabilities = {
  isWebAuthnSupported: isWebAuthnSupported(),
  isPlatformAuthAvailable: await isPlatformAuthenticatorAvailable(),
  isMobile: isMobileDevice(),
};

// Selects optimal auth method
const method = getRecommendedAuthMethod();
// Returns: 'webauthn' | 'wallet'
```

#### **Authentication Methods**

**🖥️ Desktop/Supported Devices:**

- **WebAuthn Passkeys**: Hardware-backed biometric authentication
- **Requirements**: Platform authenticators available + not mobile

**📱 Mobile/Limited Devices:**

- **Wallet Signature Authentication**: Cryptographic wallet signing
- **Requirements**: Connected wallet with signing capability

#### **Session Persistence**

- ✅ **Passkey sessions remain active** when wallets are disconnected
- ✅ **Navbar displays authenticated state** with wallet address
- ✅ **Security maintained** with 24-hour automatic expiration
- ✅ **Wallet switching** properly logs out sessions for different addresses
- ✅ **Seamless reconnection** maintains authentication for the same wallet

**Example Flow:**

1. Connect wallet → System detects device capabilities
2. **Desktop**: Offers WebAuthn passkey registration
3. **Mobile**: Offers wallet signature authentication
4. Authentication persists independently of wallet connection
5. Automatic method switching based on device capabilities

### **How Wallet Signature → Passkey Encryption Works**

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

## 🔒 **Encryption & Decryption System**

The application provides **end-to-end encryption** capabilities with **deterministic key derivation** for cross-device compatibility:

### **Encrypt Tab** 📝

- **Deterministic Encryption**: Uses passkey-derived master key for AES-GCM encryption
- **Unique IV Generation**: Each message encrypted with cryptographically secure random IV
- **Base64 Output**: Encrypted data encoded for easy storage and transmission
- **Authentication Required**: Only available when user is authenticated with passkey

### **Decrypt Tab** 🔓

- **Seamless Decryption**: Automatically extracts IV and decrypts using stored master key
- **Cross-Device Compatibility**: Same encrypted messages decrypt correctly on any device
- **Error Handling**: Clear feedback for invalid messages or authentication issues
- **Memory-Only Keys**: Master keys exist only in memory during authenticated sessions

### **Cryptographic Flow**

```
Message → AES-GCM(masterKey, randomIV) → IV + encryptedData → base64

base64 → extract IV + encryptedData → AES-GCM(masterKey, IV) → Message
```

### **Key Features**

- ✅ **Deterministic Keys**: Same wallet address = same encryption key across devices
- ✅ **AES-GCM Mode**: Authenticated encryption with integrity verification
- ✅ **Secure IV**: 12-byte cryptographically secure random initialization vectors
- ✅ **Base64 Encoding**: Safe for text storage and transmission
- ✅ **Passkey Protection**: Encryption keys require biometric authentication
- ✅ **Zero Storage**: Sensitive keys never persisted in browser storage

### **Usage Example**

1. **Connect Wallet** → Authenticate with passkey
2. **Switch to Encrypt Tab** → Enter message → Click "Encrypt Message"
3. **Copy Base64 Output** → Can be shared or stored securely
4. **Switch to Decrypt Tab** → Paste encrypted message → Click "Decrypt Message"
5. **View Original Message** → Successfully decrypted with same key

## 🏗️ **Architecture Benefits**

### **Security Properties**

- **🔐 End-to-End Encryption**: Master keys encrypted with AES-GCM
- **🔑 Deterministic Derivation**: Same wallet → same keys (recoverable)
- **🔗 Wallet Isolation**: Passkeys automatically invalidated when switching wallets
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

**Note**: The development server runs with HTTPS enabled for secure context features like WebAuthn. You'll need to accept the self-signed certificate warning in your browser when accessing `https://localhost:5173/`.

### 3. Build for Production

```bash
bun run build
```

## 🔌 Configuration

### Wagmi Setup (`src/wagmi.ts`)

```typescript
import { http, createConfig } from "wagmi";
import { arbitrum, mainnet } from "wagmi/chains";
import { injected, walletConnect } from "wagmi/connectors";

export const config = createConfig({
  chains: [arbitrum, mainnet],
  connectors: [
    injected(), // MetaMask, Rabby, etc.
    walletConnect({
      projectId: "2f05a7db73ba2b8b6a26c28c1e1a1b1b", // Test project ID (replace with your own for production)
      showQrModal: true,
    }),
  ],
  transports: {
    [arbitrum.id]: http(),
    [mainnet.id]: http(),
  },
});
```

### WalletConnect Setup

#### **Environment Variables** 🔧

Create a `.env` file in your project root:

```bash
# .env
VITE_WALLETCONNECT_PROJECT_ID=2f05a7db73ba2b8b6a26c28c1e1a1b1b
```

**Note:** `.env` files are automatically ignored by git for security.

#### **For Development/Testing** 🧪

You can test the WalletConnect UI and functionality with the included test project ID in `.env`:

```typescript
walletConnect({
  projectId: import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || "demo-project-id",
  showQrModal: true,
}),
```

**What Works in Test Mode:**

- ✅ WalletConnect button appears in wallet selection
- ✅ QR modal displays when clicked
- ✅ UI components render correctly
- ✅ No build errors or runtime crashes

**What Doesn't Work in Test Mode:**

- ❌ Actual wallet connections (requires valid project ID)
- ❌ QR code scanning by mobile wallets
- ❌ Real transaction signing

#### **For Production** 🚀

1. **Create a WalletConnect Project**:
   - Go to [WalletConnect Cloud](https://cloud.walletconnect.com/)
   - Sign up/Sign in to your account
   - Create a new project
   - Copy your Project ID

2. **Update Configuration**:
   - Replace the test project ID in `src/wagmi.ts` with your actual Project ID
   - The QR modal will enable real wallet connections

3. **Supported Wallets**:
   - MetaMask Mobile
   - Trust Wallet
   - Rainbow
   - Coinbase Wallet
   - Argent
   - And 400+ more...

### Tailwind v4 Setup (`vite.config.ts`)

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
});
```

## 🚀 Deployment

### GitHub Pages Setup

The application is configured for automatic deployment to GitHub Pages with the subdomain `wallet.inbytes.xyz`.

#### Prerequisites

1. **Enable GitHub Pages** in your repository settings:
   - Go to Settings → Pages
   - Set source to "GitHub Actions"
   - Set custom domain to `wallet.inbytes.xyz`

2. **Configure DNS** for the subdomain:
   - Add a CNAME record for `wallet.inbytes.xyz` pointing to `0xCryptonauta.github.io`
   - This enables the custom subdomain deployment

#### Automatic Deployment

- **Trigger**: Pushes to the `main` branch
- **Build**: Uses Node.js 18 with npm caching
- **Deploy**: Automatically deploys to GitHub Pages with the CNAME file

#### Manual Build & Preview

```bash
# Build for production
npm run build

# Preview production build locally
npm run preview
```

### PWA Features

The app includes Progressive Web App (PWA) capabilities:

- **Offline Support**: Static assets cached for offline access
- **Installable**: Can be installed as a native app on devices
- **Auto-Updates**: Service worker automatically updates the app
- **Fast Loading**: Cached resources load instantly

## 📱 **Application Tabs**

The application provides multiple tabs for different functionalities:

- **🔐 Auth Tab**: Passkey registration and authentication
- **✍️ Sign Tab**: Message signing with connected wallet
- **✅ Verify Tab**: Signature verification
- **🔒 Encrypt Tab**: End-to-end encryption using passkey-derived keys
- **🔓 Decrypt Tab**: Decryption of encrypted messages

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
