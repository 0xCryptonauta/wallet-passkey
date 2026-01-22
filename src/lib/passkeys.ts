// Fixed challenge for development - in production, this should be generated server-side
const uri = "https://wallet.inbytes.xyz";

import { x25519 } from "@noble/curves/ed25519.js";

const FIXED_CHALLENGE = `

⚠️ Only sign this message on ${uri}

This signature proves you own this wallet.
It will generate a key to encrypt and decrypt your data.

URI: ${uri}
Version: 1

-----------------------------------------

⚠️ Firma este mensaje únicamente en ${uri}

Esta firma prueba que es su billetera.
Se usará para generar una clave que cifra y descifra sus datos.

URI: ${uri}
Versión: 1
`;

// Configuration
const APP_VERSION = "wallet-passkey-app-v1";

// Pre-computed base64url encoded challenge for verification
const EXPECTED_CHALLENGE_B64URL = base64ToBase64Url(
  btoa(String.fromCharCode(...new TextEncoder().encode(FIXED_CHALLENGE))),
);

/**
 * Convert base64url to base64
 */
function base64UrlToBase64(base64Url: string): string {
  return base64Url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(base64Url.length / 4) * 4, "=");
}

/**
 * Convert base64 to base64url
 */
function base64ToBase64Url(base64: string): string {
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Derive X25519 keypair from root key
 * (publicX, privateX) = x25519DeriveKeypair(rootKeyX)
 */
export function x25519DeriveKeypair(rootKey: Uint8Array): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  // For now, use the root key directly as X25519 private key
  // In a full implementation, we might use HKDF to derive: privateX = HKDF(rootKeyX, "x25519-device-key")
  // But for simplicity and security, using the 32-byte root key directly works
  const privateKey = rootKey;

  // Derive the corresponding public key
  const publicKey = x25519.getPublicKey(privateKey);

  return { publicKey, privateKey };
}

/**
 * Derive shared secret using X25519 ECDH
 * Used for peer-to-peer encryption/decryption
 */
export async function x25519DeriveSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<Uint8Array> {
  // Perform ECDH key exchange
  const sharedSecret = x25519.getSharedSecret(privateKey, publicKey);

  // Use HKDF to derive final AES key from shared secret
  // This provides better key derivation and domain separation
  return deriveAESKeyFromSharedSecret(sharedSecret);
}

/**
 * Derive AES key from X25519 shared secret using HKDF
 */
async function deriveAESKeyFromSharedSecret(
  sharedSecret: Uint8Array,
): Promise<Uint8Array> {
  // Import shared secret as key material for HKDF
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    sharedSecret.buffer.slice(
      sharedSecret.byteOffset,
      sharedSecret.byteOffset + sharedSecret.byteLength,
    ) as ArrayBuffer,
    { name: "HKDF" },
    false,
    ["deriveBits"],
  );

  // Create salt (empty for shared secret derivation)
  const salt = new Uint8Array(0);

  // Create info for domain separation
  const info = new TextEncoder().encode("x25519-shared-secret-aes-key");

  // Derive 32-byte AES key using HKDF
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt,
      info: info,
    },
    keyMaterial,
    256, // 32 bytes
  );

  return new Uint8Array(derivedBits);
}

/**
 * Derive a master key from a signature using HKDF (Web Crypto API)
 * Exported for future use in full cryptographic implementation
 */
export async function deriveMasterKey(
  signature: string,
  userAddress: string,
): Promise<Uint8Array> {
  // For wallet signatures (hex), convert to bytes
  let signatureBytes: Uint8Array;
  if (signature.startsWith("0x")) {
    // Wallet signature - hex format
    const cleanSignature = signature.slice(2);
    signatureBytes = new Uint8Array(
      cleanSignature.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
    );
  } else {
    // Passkey signature - base64 format
    signatureBytes = new Uint8Array(
      atob(signature)
        .split("")
        .map((c) => c.charCodeAt(0)),
    );
  }

  // Import signature as key material for HKDF
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    signatureBytes.buffer.slice(
      signatureBytes.byteOffset,
      signatureBytes.byteOffset + signatureBytes.byteLength,
    ) as ArrayBuffer,
    { name: "HKDF" },
    false,
    ["deriveBits"],
  );

  // Create salt from app version
  const salt = new TextEncoder().encode(APP_VERSION);

  // Create info from user address
  const info = new TextEncoder().encode(userAddress);

  // Derive master key using HKDF
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt,
      info: info,
    },
    keyMaterial,
    256, // 32 bytes
  );

  return new Uint8Array(derivedBits);
}

/**
 * Phase 4: Wrap the master key using AES-GCM
 * Uses credential ID for deterministic wrapping key derivation
 * Exported for future use in full cryptographic implementation
 */
export async function wrapMasterKey(
  masterKey: Uint8Array,
  credentialId: string,
): Promise<{ wrappedKey: string; iv: string }> {
  // Use credential ID for deterministic key derivation
  const credentialBytes = new TextEncoder().encode(credentialId);

  // Derive wrapping key from credential ID using HKDF
  const wrappingKeyMaterial = await crypto.subtle.importKey(
    "raw",
    credentialBytes.buffer.slice(
      credentialBytes.byteOffset,
      credentialBytes.byteOffset + credentialBytes.byteLength,
    ),
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );

  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("passkey-wrap"),
      info: new TextEncoder().encode("encryption"),
    },
    wrappingKeyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  // Generate cryptographically secure IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt master key using AES-GCM
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    masterKey as any, // TypeScript is overly strict about BufferSource types in Web Crypto API
  );

  // Return base64 encoded wrapped key and IV
  return {
    wrappedKey: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

/**
 * Unwrap the master key using AES-GCM
 * Uses credential ID for deterministic wrapping key derivation
 * Exported for future use in full cryptographic implementation
 */
export async function unwrapMasterKey(
  wrappedKey: string,
  iv: string,
  credentialId: string,
): Promise<Uint8Array> {
  // Use credential ID for deterministic key derivation (same as wrapping)
  const credentialBytes = new TextEncoder().encode(credentialId);

  // Derive the same wrapping key from credential ID
  const wrappingKeyMaterial = await crypto.subtle.importKey(
    "raw",
    credentialBytes.buffer.slice(
      credentialBytes.byteOffset,
      credentialBytes.byteOffset + credentialBytes.byteLength,
    ),
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );

  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("passkey-wrap"),
      info: new TextEncoder().encode("encryption"),
    },
    wrappingKeyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  // Decode the wrapped key and IV
  const encryptedData = new Uint8Array(
    atob(wrappedKey)
      .split("")
      .map((c) => c.charCodeAt(0)),
  );
  const ivBytes = new Uint8Array(
    atob(iv)
      .split("")
      .map((c) => c.charCodeAt(0)),
  );

  // Decrypt using AES-GCM
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    wrappingKey,
    encryptedData,
  );

  return new Uint8Array(decrypted);
}

// Types for passkey operations
export interface PasskeyCredential {
  id: string;
  walletAddress: string;
  publicKey: string;
  counter: number;
  created: number;
  wrappedKey?: string;
  iv?: string;
  x25519PublicKey?: string;
}

export interface AuthenticationResult {
  success: boolean;
  credential?: PasskeyCredential;
  signature?: string;
  masterKey?: Uint8Array;
  error?: string;
}

/**
 * Register a new passkey for the user
 * Prioritizes platform authenticators (local device) over roaming authenticators
 */
export async function registerPasskey(
  walletSignMessage: (message: string) => Promise<string>,
  walletAddress: string,
): Promise<AuthenticationResult> {
  try {
    // First, ask user to sign the challenge with their wallet
    let walletSignature: string;
    try {
      walletSignature = await walletSignMessage(FIXED_CHALLENGE);
    } catch (error) {
      return {
        success: false,
        error: "Wallet signature required for passkey creation",
      };
    }

    // Derive deterministic master key from wallet signature
    const masterKey = await deriveMasterKey(walletSignature, walletAddress);

    // Derive X25519 public key from master key for peer messaging
    const { publicKey: x25519PublicKey } = x25519DeriveKeypair(masterKey);

    // Store master key temporarily until first authentication
    // Note: Only master key is stored temporarily - X25519 keys are re-derived when needed
    sessionStorage.setItem(
      `master-key-${walletAddress}`,
      JSON.stringify(Array.from(masterKey)),
    );

    // Store X25519 public key immediately (safe to store in plaintext)
    sessionStorage.setItem(
      `x25519-public-key-${walletAddress}`,
      JSON.stringify(Array.from(x25519PublicKey)),
    );

    // Check if WebAuthn is supported
    if (!navigator.credentials || !navigator.credentials.create) {
      return {
        success: false,
        error: "WebAuthn is not supported in this browser",
      };
    }

    // Check if platform authenticators are available
    const platformAuthAvailable = await isPlatformAuthenticatorAvailable();

    let authenticatorSelection: AuthenticatorSelectionCriteria;

    if (platformAuthAvailable) {
      // Platform authenticators available - require platform attachment for local-only passkeys
      console.log(
        "Platform authenticators available - creating local device passkey",
      );
      authenticatorSelection = {
        authenticatorAttachment: "platform", // Require platform authenticators (local device only)
        userVerification: "required", // Require user verification
        residentKey: "required", // Store credential on authenticator
      };
    } else {
      // No platform authenticators - fall back to roaming authenticators
      console.log(
        "No platform authenticators - falling back to roaming passkeys (cloud/phone/tablet)",
      );
      authenticatorSelection = {
        userVerification: "required", // Require user verification
        residentKey: "required", // Store credential on authenticator
      };
    }

    // Create credential creation options
    const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions =
      {
        challenge: new TextEncoder().encode(FIXED_CHALLENGE),
        rp: {
          name: "Wallet Passkey",
          id: window.location.hostname,
        },
        user: {
          id: new TextEncoder().encode(walletAddress),
          name: walletAddress,
          displayName: `Wallet ${walletAddress.slice(
            0,
            6,
          )}...${walletAddress.slice(-4)}`,
        },
        pubKeyCredParams: [
          { alg: -7, type: "public-key" }, // ES256
          { alg: -257, type: "public-key" }, // RS256
        ],
        authenticatorSelection,
        timeout: 60000, // 60 seconds
        attestation: "direct",
      };

    // Create the credential
    const credential = (await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    })) as PublicKeyCredential;

    if (!credential) {
      return { success: false, error: "Failed to create passkey" };
    }

    // Extract credential data
    const response = credential.response as AuthenticatorAttestationResponse;
    const publicKey = response.getPublicKey();
    const publicKeyString = btoa(
      String.fromCharCode(...new Uint8Array(publicKey!)),
    );

    const passkeyCredential: PasskeyCredential = {
      id: credential.id,
      walletAddress,
      publicKey: publicKeyString,
      counter: 0, // Initialize counter
      created: Date.now(),
    };

    // Store the credential for this wallet
    storeCredential(walletAddress, passkeyCredential);

    return { success: true, credential: passkeyCredential };
  } catch (error) {
    console.error("Passkey registration failed:", error);
    return {
      success: false,
      error:
        error instanceof Error
          ? error.message
          : "Unknown error during registration",
    };
  }
}

/**
 * Authenticate using a stored passkey for a specific wallet
 */
export async function authenticateWithPasskey(
  walletAddress?: string,
): Promise<AuthenticationResult> {
  try {
    const storedCredentials = getStoredCredentials(walletAddress);

    if (storedCredentials.length === 0) {
      return {
        success: false,
        error:
          "No passkeys registered for this wallet. Please register a passkey first.",
      };
    }

    // Use the first (most recent) credential for now
    const credentialId = storedCredentials[0].id;

    const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions =
      {
        challenge: new TextEncoder().encode(FIXED_CHALLENGE),
        allowCredentials: [
          {
            id: new Uint8Array(
              atob(base64UrlToBase64(credentialId))
                .split("")
                .map((c) => c.charCodeAt(0)),
            ),
            type: "public-key",
          },
        ],
        userVerification: "required",
        timeout: 60000,
      };

    const assertion = (await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions,
    })) as PublicKeyCredential;

    if (!assertion) {
      return { success: false, error: "Authentication failed" };
    }

    // Verify the assertion (in a real implementation, this would be done server-side)
    const clientDataJSON = new TextDecoder().decode(
      (assertion.response as AuthenticatorAssertionResponse).clientDataJSON,
    );

    // Parse client data to verify challenge
    const clientData = JSON.parse(clientDataJSON);
    if (clientData.challenge !== EXPECTED_CHALLENGE_B64URL) {
      console.log("Challenge mismatch:", {
        received: clientData.challenge,
        expected: EXPECTED_CHALLENGE_B64URL,
      });
      return { success: false, error: "Challenge verification failed" };
    }

    // Extract the signature for cryptographic operations
    const signature = btoa(
      String.fromCharCode(
        ...new Uint8Array(
          (assertion.response as AuthenticatorAssertionResponse).signature,
        ),
      ),
    );

    // Handle master key wrapping/unwrapping for deterministic encryption
    let masterKey: Uint8Array | undefined;

    if (storedCredentials[0].wrappedKey && storedCredentials[0].iv) {
      // Subsequent authentication: unwrap the stored master key
      try {
        masterKey = await unwrapMasterKey(
          storedCredentials[0].wrappedKey,
          storedCredentials[0].iv,
          credentialId,
        );
      } catch (error) {
        console.error("Failed to unwrap master key:", error);
        return { success: false, error: "Failed to unwrap encryption key" };
      }
    } else {
      // First authentication: check for temporary master key and wrap it
      const tempMasterKeyData = sessionStorage.getItem(
        `master-key-${walletAddress}`,
      );
      const tempX25519PublicKeyData = sessionStorage.getItem(
        `x25519-public-key-${walletAddress}`,
      );

      if (tempMasterKeyData && tempX25519PublicKeyData) {
        try {
          const tempMasterKey = new Uint8Array(JSON.parse(tempMasterKeyData));
          const tempX25519PublicKey = new Uint8Array(
            JSON.parse(tempX25519PublicKeyData),
          );

          // Wrap the master key with credential ID (deterministic)
          const { wrappedKey, iv } = await wrapMasterKey(
            tempMasterKey,
            credentialId,
          );

          // Update credential with wrapped key and X25519 public key
          // Only X25519 public key is stored in localStorage - master key exists only wrapped
          const updatedCredential = {
            ...storedCredentials[0],
            wrappedKey,
            iv,
            x25519PublicKey: btoa(String.fromCharCode(...tempX25519PublicKey)),
          };
          storeCredential(walletAddress!, updatedCredential);

          // Clean up temporary storage
          sessionStorage.removeItem(`master-key-${walletAddress}`);
          sessionStorage.removeItem(`x25519-public-key-${walletAddress}`);

          masterKey = tempMasterKey;
        } catch (error) {
          console.error("Failed to wrap master key:", error);
          return { success: false, error: "Failed to setup encryption key" };
        }
      } else {
        return {
          success: false,
          error:
            "No encryption key available. Please re-register your passkey.",
        };
      }
    }

    return {
      success: true,
      credential: storedCredentials[0],
      signature,
      masterKey,
    };
  } catch (error) {
    console.error("Passkey authentication failed:", error);
    return {
      success: false,
      error:
        error instanceof Error
          ? error.message
          : "Unknown error during authentication",
    };
  }
}

/**
 * Get all stored passkey credentials for a specific wallet
 */
export function getStoredCredentials(
  walletAddress?: string,
): PasskeyCredential[] {
  try {
    const allCredentials: Record<string, PasskeyCredential[]> = JSON.parse(
      localStorage.getItem("wallet-passkeys-v2") || "{}",
    );

    if (!walletAddress) {
      // Return all credentials from all wallets (for migration/display purposes)
      return Object.values(allCredentials).flat();
    }

    return allCredentials[walletAddress] || [];
  } catch (error) {
    console.error("Failed to get stored credentials:", error);
    return [];
  }
}

/**
 * Store a passkey credential for a specific wallet
 */
export function storeCredential(
  walletAddress: string,
  credential: PasskeyCredential,
): void {
  try {
    const allCredentials: Record<string, PasskeyCredential[]> = JSON.parse(
      localStorage.getItem("wallet-passkeys-v2") || "{}",
    );

    if (!allCredentials[walletAddress]) {
      allCredentials[walletAddress] = [];
    }

    // Check if credential already exists (avoid duplicates)
    const existingIndex = allCredentials[walletAddress].findIndex(
      (c) => c.id === credential.id,
    );
    if (existingIndex >= 0) {
      allCredentials[walletAddress][existingIndex] = credential;
    } else {
      allCredentials[walletAddress].push(credential);
    }

    localStorage.setItem("wallet-passkeys-v2", JSON.stringify(allCredentials));
  } catch (error) {
    console.error("Failed to store credential:", error);
  }
}

/**
 * Clear all stored passkeys for a specific wallet
 */
export function clearStoredCredentials(walletAddress?: string): void {
  if (!walletAddress) {
    // Clear all passkeys from all wallets
    localStorage.removeItem("wallet-passkeys-v2");
    // Also clear legacy storage
    localStorage.removeItem("wallet-passkeys");
    return;
  }

  try {
    const allCredentials: Record<string, PasskeyCredential[]> = JSON.parse(
      localStorage.getItem("wallet-passkeys-v2") || "{}",
    );

    delete allCredentials[walletAddress];

    if (Object.keys(allCredentials).length === 0) {
      localStorage.removeItem("wallet-passkeys-v2");
    } else {
      localStorage.setItem(
        "wallet-passkeys-v2",
        JSON.stringify(allCredentials),
      );
    }
  } catch (error) {
    console.error("Failed to clear credentials:", error);
  }
}

/**
 * Delete a specific passkey by credential ID and wallet address
 */
export function deletePasskey(
  credentialId: string,
  walletAddress?: string,
): boolean {
  if (!walletAddress) {
    // For backward compatibility, try to find the credential in any wallet
    try {
      const allCredentials: Record<string, PasskeyCredential[]> = JSON.parse(
        localStorage.getItem("wallet-passkeys-v2") || "{}",
      );

      for (const [addr, credentials] of Object.entries(allCredentials)) {
        const filteredCredentials = credentials.filter(
          (cred) => cred.id !== credentialId,
        );
        if (filteredCredentials.length < credentials.length) {
          if (filteredCredentials.length === 0) {
            delete allCredentials[addr];
          } else {
            allCredentials[addr] = filteredCredentials;
          }
          localStorage.setItem(
            "wallet-passkeys-v2",
            JSON.stringify(allCredentials),
          );
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error("Failed to delete passkey:", error);
      return false;
    }
  }

  // Delete from specific wallet
  try {
    const allCredentials: Record<string, PasskeyCredential[]> = JSON.parse(
      localStorage.getItem("wallet-passkeys-v2") || "{}",
    );

    if (allCredentials[walletAddress]) {
      const filteredCredentials = allCredentials[walletAddress].filter(
        (cred) => cred.id !== credentialId,
      );

      if (filteredCredentials.length < allCredentials[walletAddress].length) {
        if (filteredCredentials.length === 0) {
          delete allCredentials[walletAddress];
        } else {
          allCredentials[walletAddress] = filteredCredentials;
        }
        localStorage.setItem(
          "wallet-passkeys-v2",
          JSON.stringify(allCredentials),
        );
        return true;
      }
    }
    return false;
  } catch (error) {
    console.error("Failed to delete passkey:", error);
    return false;
  }
}

/**
 * Check if the user has any registered passkeys for a specific wallet
 */
export function hasRegisteredPasskeys(walletAddress?: string): boolean {
  return getStoredCredentials(walletAddress).length > 0;
}

/**
 * Check if WebAuthn is supported in the current browser
 */
export function isWebAuthnSupported(): boolean {
  return !!(navigator.credentials && navigator.credentials.create);
}

/**
 * Check if platform authenticators are available
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;

  try {
    // Check if user-verifying platform authenticators are available
    const available =
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    return available;
  } catch (error) {
    console.warn("Platform authenticator check failed:", error);
    return false;
  }
}

/**
 * Check if device is mobile
 */
export function isMobileDevice(): boolean {
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
    navigator.userAgent,
  );
}

/**
 * Determine the best authentication method for the current device
 */
export async function getRecommendedAuthMethod(): Promise<
  "webauthn" | "wallet"
> {
  const webAuthnSupported = isWebAuthnSupported();
  const platformAuthAvailable = await isPlatformAuthenticatorAvailable();
  const isMobile = isMobileDevice();

  // Use WebAuthn if supported and platform authenticators are available
  // Avoid WebAuthn on mobile devices due to poor support
  if (webAuthnSupported && platformAuthAvailable && !isMobile) {
    return "webauthn";
  }

  // Default to wallet authentication (works everywhere)
  return "wallet";
}

/**
 * Get master key for a cryptographic operation (requires biometric verification)
 * This performs WebAuthn assertion and temporarily unwraps the master key
 * without persisting authentication state
 */
export async function getMasterKeyForOperation(
  walletAddress: string,
): Promise<{ success: boolean; masterKey?: Uint8Array; error?: string }> {
  try {
    const storedCredentials = getStoredCredentials(walletAddress);

    if (storedCredentials.length === 0) {
      return {
        success: false,
        error:
          "No passkeys registered for this wallet. Please register a passkey first.",
      };
    }

    // Use the first (most recent) credential
    const credentialId = storedCredentials[0].id;

    const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions =
      {
        challenge: new TextEncoder().encode(FIXED_CHALLENGE),
        allowCredentials: [
          {
            id: new Uint8Array(
              atob(base64UrlToBase64(credentialId))
                .split("")
                .map((c) => c.charCodeAt(0)),
            ),
            type: "public-key",
          },
        ],
        userVerification: "required",
        timeout: 60000,
      };

    const assertion = (await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions,
    })) as PublicKeyCredential;

    if (!assertion) {
      return { success: false, error: "Authentication failed" };
    }

    // Verify the assertion (in a real implementation, this would be done server-side)
    const clientDataJSON = new TextDecoder().decode(
      (assertion.response as AuthenticatorAssertionResponse).clientDataJSON,
    );

    // Parse client data to verify challenge
    const clientData = JSON.parse(clientDataJSON);
    if (clientData.challenge !== EXPECTED_CHALLENGE_B64URL) {
      return { success: false, error: "Challenge verification failed" };
    }

    // Get the wrapped key from stored credentials
    if (!storedCredentials[0].wrappedKey || !storedCredentials[0].iv) {
      return {
        success: false,
        error: "No encryption key available. Please re-register your passkey.",
      };
    }

    // Unwrap the master key for this operation
    const masterKey = await unwrapMasterKey(
      storedCredentials[0].wrappedKey,
      storedCredentials[0].iv,
      credentialId,
    );

    return { success: true, masterKey };
  } catch (error) {
    console.error("Failed to get master key for operation:", error);
    return {
      success: false,
      error:
        error instanceof Error
          ? error.message
          : "Unknown error during key retrieval",
    };
  }
}

/**
 * Authenticate using wallet signature (fallback for WebAuthn)
 */
export async function authenticateWithWallet(
  walletSignMessage: (message: string) => Promise<string>,
  walletAddress: string,
): Promise<AuthenticationResult> {
  try {
    // Create authentication challenge
    const authChallenge = `Authenticate wallet ownership\n\nAddress: ${walletAddress}\nTimestamp: ${Date.now()}\n\nSign this message to authenticate.`;

    // Sign the challenge
    const signature = await walletSignMessage(authChallenge);

    // Verify signature format (basic check)
    if (!signature || typeof signature !== "string") {
      return {
        success: false,
        error: "Invalid signature received",
      };
    }

    // In production, verify signature cryptographically
    // For now, we trust the wallet signature

    return {
      success: true,
      credential: {
        id: `wallet-auth-${walletAddress}`,
        walletAddress,
        publicKey: "", // Not needed for wallet auth
        counter: Date.now(),
        created: Date.now(),
      },
    };
  } catch (error) {
    console.error("Wallet authentication failed:", error);
    return {
      success: false,
      error:
        error instanceof Error ? error.message : "Wallet authentication failed",
    };
  }
}
