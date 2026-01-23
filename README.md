# 🔐 Wallet Passkey - Enterprise Web3 Authentication

A revolutionary Web3 wallet application featuring **hardware-backed passkey authentication** with **enterprise-grade cryptography** and **X25519 peer-to-peer messaging**. Combines Web3 wallet ownership verification with biometric security for the ultimate in secure, user-friendly authentication and encrypted communication.

## 🌟 **Key Features**

- 🔐 **Hardware-Backed Security**: WebAuthn passkeys with Touch ID, Face ID, and security keys
- 🔑 **Wallet Ownership Verification**: Cryptographic proof of wallet control
- 🔒 **End-to-End Encryption**: Deterministic AES-GCM encryption with passkey-derived keys
- 🔄 **Cross-Device Compatibility**: Same encryption keys work across all devices
- **Wallet-Specific Binding**: Passkeys are cryptographically tied to wallet addresses
- 🛡️ **Enterprise Cryptography**: HKDF key derivation + AES-GCM encryption + X25519 ECDH
- ⚡ **Zero-Knowledge Architecture**: Sensitive keys never stored in plaintext
- 🎯 **Biometric UX**: Hardware authentication without passwords
- 🔗 **Peer-to-Peer Messaging**: X25519-based secure communication between users
- 🚀 **Production Ready**: Built with modern Web3 and crypto standards

---

# 🔐 Wallet-Bound X25519 Messaging Model

A secure, wallet-authenticated, device-bound messaging model using modern cryptography primitives.

---

## ✨ Overview

This model enables two users to derive a shared symmetric encryption key without ever transmitting it, using:

- Wallet signatures for identity proof
- HKDF for deterministic key derivation
- X25519 for key agreement
- AES-GCM for message encryption
- Passkeys (WebAuthn) for secure private key storage

# UX Flow

## 🧱 Setup (User X)

### 1. Wallet Identity Proof

User **X** signs a fixed challenge containing:

- domain
- purpose

This signature proves wallet ownership.

> ⚠️ The signature is **not** used directly as a private key.

---

### 2. Deterministic Root Key Derivation

The wallet signature is fed into HKDF to derive a deterministic root key.

```text
rootKeyX = HKDF(
  input = signatureX,
  salt = app-domain,
  info = userX + chainId
)
```

### 3. X25519 Key Pair Derivation

- The root key is used to derive an X25519 private key.

      privateX = HKDF(rootKeyX, "x25519-device-key")

- The corresponding public key is derived using X25519.

      publicX = X25519(privateX)

### 4. Secure Storage & Publication

- PrivateX is stored encrypted behind a passkey (WebAuthn)

- PublicX is shared publicly

---

### 5. UserZ → UserX

- User Z has their own X25519 key pair:

      (privateZ, publicZ)

1. Shared Secret Derivation
   - User Z derives a shared secret using:
     - their private key

     - user X’s public key

   ```
   sharedZX = X25519(privateZ, publicX)
   ```

2. Symmetric Key Derivation
   - The shared secret is expanded into an AES key using HKDF.

   ```
   aesKeyZX = HKDF(sharedZX)
   ```

3. Message Encryption
   - User Z encrypts the message using AES-GCM.

   ```
   ciphertext = AES-GCM-ENCRYPT(aesKeyZX, message)
   ```

4. Message Transmission
   - User Z sends the following to user X:

   ```
   (publicZ, ciphertext)
   ```

---

### 6. UserX Receives

1. Shared Secret Derivation
   - User X derives the same shared secret using:
     - their private key
     - user Z’s public key

   ```
   sharedXZ = X25519(privateX, publicZ)
   ```

2. Symmetric Key Derivation

   ```
   aesKeyXZ = HKDF(sharedXZ)
   ```

3. Message Decryption

   ```
   message = AES-GCM-DECRYPT(aesKeyXZ, ciphertext)
   ```

4. Result

   ```
   sharedZX == sharedXZ
   aesKeyZX == aesKeyXZ
   ```

5. User X successfully decrypts the message.

---

---

### **_🔒 Security Notes_**

- X25519 is used only for key agreement, never for encryption
- AES-GCM is used for authenticated encryption
- HKDF is mandatory for key derivation
- Private keys never leave the device
- Public keys must be authenticated (wallet signature, Ed25519, TLS, etc.) to prevent MITM attacks

---

### **_🧠 Mental Model Summary_**

- Wallet → Identity proof
- HKDF → Deterministic root
- X25519 → Shared secret
- HKDF → Symmetric key
- AES → Encrypted messages
- Passkey→ Secure private key storage

---

## 🔒 **Encryption & Decryption System**

The application provides **dual-mode encryption** capabilities: **self-encryption** (personal messages) and **peer-to-peer encryption** (secure messaging between users) using X25519 ECDH key agreement.

### **Encrypt Tab** 📝

The Encrypt tab supports two encryption modes:

#### **Mode 1: Encrypt for Myself** (Self-Encryption)

- **Per-Operation Biometric Verification**: Each encryption requires fresh fingerprint/face/Touch ID
- **Deterministic Encryption**: Uses passkey-derived master key directly for AES-GCM encryption
- **Cross-Device Compatibility**: Same messages decrypt correctly on any authenticated device
- **Use Case**: Personal encrypted notes, secure storage

#### **Mode 2: Encrypt for Someone Else** (Peer-to-Peer)

- **X25519 ECDH**: Uses Elliptic Curve Diffie-Hellman for shared secret derivation
- **Recipient Public Key**: Input the recipient's X25519 public key (shared via Auth tab)
- **Shared Secret**: `ECDH(myPrivateKey, recipientPublicKey) → HKDF → AES Key`
- **Use Case**: Secure messaging between different users

### **Decrypt Tab** 🔓

The Decrypt tab supports corresponding decryption modes:

#### **Mode 1: Decrypt for Myself** (Self-Decryption)

- **Per-Operation Biometric Verification**: Each decryption requires fresh fingerprint/face/Touch ID
- **Seamless Decryption**: Automatically extracts IV and decrypts using temporarily unwrapped master key
- **Zero-Knowledge Keys**: Master keys never stored in memory between operations

#### **Mode 2: Decrypt from Someone Else** (Peer-to-Peer)

- **X25519 ECDH**: Uses sender's public key for shared secret derivation
- **Sender Public Key**: Input the sender's X25519 public key to decrypt
- **Shared Secret**: `ECDH(myPrivateKey, senderPublicKey) → HKDF → AES Key`
- **Perfect Security**: Messages can only be decrypted by intended recipients

### **Cryptographic Flows**

#### **Self-Encryption Flow**

```
Message → AES-GCM(masterKey, randomIV) → IV + encryptedData → base64
base64 → extract IV + encryptedData → AES-GCM(masterKey, IV) → Message
```

#### **Peer-to-Peer Encryption Flow**

```
Sender: masterKey → X25519(privateKey) → ECDH(privateKey, recipientPub) → HKDF → AES Key → Encrypt
Recipient: masterKey → X25519(privateKey) → ECDH(privateKey, senderPub) → HKDF → AES Key → Decrypt
```

### **Key Features**

- ✅ **Dual Mode Encryption**: Self-encryption + peer-to-peer messaging
- ✅ **X25519 ECDH**: Elliptic Curve Diffie-Hellman for key agreement
- ✅ **HKDF Key Derivation**: Domain separation for shared secrets
- ✅ **AES-GCM Mode**: Authenticated encryption with integrity verification
- ✅ **Secure IV**: 12-byte cryptographically secure random initialization vectors
- ✅ **Base64 Encoding**: Safe for text storage and transmission
- ✅ **Per-Operation Biometric Verification**: Each encrypt/decrypt requires fresh authentication
- ✅ **Zero Storage**: Sensitive keys never stored in memory between operations

### **Usage Examples**

#### **Self-Encryption Example**

1. **Connect Wallet** → Authenticate with passkey
2. **Encrypt Tab** → Select "Encrypt for Myself" → Enter message → Encrypt
3. **Decrypt Tab** → Select "Decrypt for Myself" → Paste encrypted message → Decrypt

#### **Peer-to-Peer Example**

1. **User A**: Auth tab → Copy X25519 public key → Share with User B
2. **User B**: Auth tab → Copy X25519 public key → Share with User A
3. **User A**: Encrypt tab → "Encrypt for Someone Else" → Input User B's public key → Encrypt message
4. **User B**: Decrypt tab → "Decrypt from Someone Else" → Input User A's public key → Decrypt message

## 🔑 **Public Key Management**

### **X25519 Public Key Display**

- **Location**: Auth tab, under wallet address and above creation date
- **Format**: Base64-encoded 32-byte X25519 public key
- **Copy Functionality**: One-click copying to clipboard with success feedback
- **Security**: Public keys are safe to share (no private information revealed)

### **Key Storage Architecture**

- **localStorage**: Only X25519 public keys (plaintext, shareable)
- **Passkey-protected**: Master key exists only wrapped behind WebAuthn
- **Runtime**: Private keys derived on-demand, never persisted
- **Zero-knowledge**: Sensitive keys never stored between operations

## 🏗️ **Architecture Benefits**

### **Security Properties**

- **🔐 Dual-Mode Encryption**: Self-encryption + X25519 peer-to-peer messaging
- **🔑 Deterministic Derivation**: Same wallet → same keys (recoverable)
- **🔗 Wallet Isolation**: Passkeys automatically invalidated when switching wallets
- **🛡️ Hardware Security**: TPM/TEE-backed key operations with WebAuthn
- **🚫 Anti-Phishing**: Domain verification in challenges
- **⚡ Zero-Knowledge Storage**: Master keys exist only wrapped, X25519 public keys only in localStorage
- **🔒 Perfect Forward Secrecy**: Each peer-to-peer message uses unique shared secret
- **🕵️ Zero-Trust**: No sensitive data in browser storage between operations

### **User Experience**

- **👆 One-Touch Authentication**: Biometric hardware UX for every operation
- **🔄 Wallet Integration**: Seamlessly connects to existing wallets
- **📱 Cross-Device**: iCloud/Google sync for passkeys and public keys
- **🚀 Fast Operations**: Hardware-accelerated cryptography
- **🔒 Passwordless**: No passwords to remember or type
- **🔗 Peer Messaging**: Share public keys for secure person-to-person communication
- **📋 Copy-Paste UX**: Easy public key sharing with copy-to-clipboard functionality

### **Technical Advantages**

- **🏢 Enterprise Grade**: FIPS-compliant algorithms (HKDF, AES-GCM, X25519)
- **🌐 Web Standards**: WebAuthn + Web Crypto API + modern cryptography
- **📊 Auditable**: Complete cryptographic operation trail
- **🔧 Extensible**: Exported functions for additional messaging features
- **⚡ Performant**: Browser-native cryptographic acceleration
- **🔄 Future-Proof**: Architecture supports additional encryption schemes

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

### WalletConnect Setup

#### **Environment Variables** 🔧

Create a `.env` file in your project root:

```bash
# .env
VITE_WALLETCONNECT_PROJECT_ID=2f05a7db73ba2b8b6a26c28c1e1a1b1b
```

### PWA Features

The app includes Progressive Web App (PWA) capabilities:

- **Offline Support**: Static assets cached for offline access
- **Installable**: Can be installed as a native app on devices
- **Auto-Updates**: Service worker automatically updates the app
- **Fast Loading**: Cached resources load instantly

## 📱 **Application Interface**

The application provides multiple tabs for different functionalities with a modern side panel for authentication:

### **Navigation Tabs**

- **✍️ Sign Tab**: Message signing with connected wallet
- **✅ Verify Tab**: Signature verification
- **🔒 Encrypt Tab**: Dual-mode encryption (self + peer-to-peer)
  - **Encrypt for Myself**: Personal secure storage
  - **Encrypt for Someone Else**: X25519-based secure messaging to other users
- **🔓 Decrypt Tab**: Dual-mode decryption (self + peer-to-peer)
  - **Decrypt for Myself**: Access personal encrypted content
  - **Decrypt from Someone Else**: X25519-based decryption of peer messages

### **Authentication Side Panel** 🔐

- **Access**: Click the "Auth" button in the navbar or authenticated wallet display
- **Features**: Passkey registration, authentication, and X25519 public key management
- **Functionality**:
  - Register and authenticate with WebAuthn passkeys
  - View and copy X25519 public key for peer-to-peer messaging
  - Hardware-backed biometric verification for all operations
- **UX**: Slides in from the right, click outside or press ESC to close
- **Mobile**: Close button (X) in top-right + back gesture support
- **Desktop**: No close button, click-outside or ESC key only

## 📝 Common Commands

| Command         | Action                                            |
| --------------- | ------------------------------------------------- |
| `bun dev`       | Starts local development server                   |
| `bun run build` | Compiles optimized production build               |
| `bun add <pkg>` | Adds a dependency using Bun's high-speed resolver |
| `bun test`      | Runs the internal Bun test runner                 |

## 🔧 Development Configuration

This project uses the following git configuration for better commit history visualization:

```bash
# Always create merge commits to preserve branch history in git graph
git config --global merge.ff false
```

This ensures that `git merge` always creates a merge commit, preserving the branch structure in the git history graph.

---

Built with ⚡️

```

```
