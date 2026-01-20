// Fixed challenge for development - in production, this should be generated server-side
const domain = "inBytes.xyz";
const uri = "https://wallet.inbytes.xyz";

const FIXED_CHALLENGE = `

⚠️ Only sign this message on ${uri}

${domain}

Wants you to sign this with your prefered wallet.

This signature proves you own this wallet.
It will generate a key to encrypt and decrypt your data.

URI: ${uri}
Version: 1

-------------------------------------------------------------------

⚠️ Firma este mensaje únicamente en ${uri}

${domain} 

Solicita que firme con su billetera preferida.

Esta firma prueba que es el dueño de esta billetera.
Se usará para generar una clave que cifra y descifra sus datos.

URI: ${uri}
Versión: 1
`;

// Configuration
const APP_VERSION = "your-app-v1";

// Pre-computed base64url encoded challenge for verification
const EXPECTED_CHALLENGE_B64URL = base64ToBase64Url(
  btoa(String.fromCharCode(...new TextEncoder().encode(FIXED_CHALLENGE)))
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
 * Phase 2: Derive a root key using HKDF (Web Crypto API)
 * Exported for future use in full cryptographic implementation
 */
export async function deriveMasterKey(
  walletSignature: string,
  userAddress: string,
  chainId: number
): Promise<Uint8Array> {
  // Convert signature to bytes (remove 0x prefix if present)
  const cleanSignature = walletSignature.startsWith("0x")
    ? walletSignature.slice(2)
    : walletSignature;

  // Convert hex signature to Uint8Array
  const signatureBytes = new Uint8Array(
    cleanSignature.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
  );

  // Import signature as key material for HKDF
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    signatureBytes.buffer.slice(
      signatureBytes.byteOffset,
      signatureBytes.byteOffset + signatureBytes.byteLength
    ),
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  // Create salt from app version
  const salt = new TextEncoder().encode(APP_VERSION);

  // Create info from user address and chain ID
  const info = new TextEncoder().encode(userAddress + chainId.toString());

  // Derive master key using HKDF
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt,
      info: info,
    },
    keyMaterial,
    256 // 32 bytes
  );

  return new Uint8Array(derivedBits);
}

/**
 * Phase 4: Wrap the master key using AES-GCM
 * Exported for future use in full cryptographic implementation
 */
export async function wrapMasterKey(
  masterKey: Uint8Array,
  passkeySignature: string
): Promise<{ wrappedKey: string; iv: string }> {
  // Convert passkey signature to bytes
  const signatureBytes = new TextEncoder().encode(passkeySignature);
  const signatureBuffer = signatureBytes.buffer.slice(
    signatureBytes.byteOffset,
    signatureBytes.byteOffset + signatureBytes.byteLength
  );

  // Derive wrapping key from passkey signature using HKDF
  const wrappingKeyMaterial = await crypto.subtle.importKey(
    "raw",
    signatureBuffer,
    { name: "HKDF" },
    false,
    ["deriveKey"]
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
    ["encrypt"]
  );

  // Generate cryptographically secure IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt master key using AES-GCM
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    masterKey as any // TypeScript is overly strict about BufferSource types in Web Crypto API
  );

  // Return base64 encoded wrapped key and IV
  return {
    wrappedKey: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

/**
 * Unwrap the master key using AES-GCM
 * Exported for future use in full cryptographic implementation
 */
export async function unwrapMasterKey(
  wrappedKey: string,
  iv: string,
  passkeySignature: string
): Promise<Uint8Array> {
  // Convert passkey signature to bytes
  const signatureBytes = new TextEncoder().encode(passkeySignature);
  const signatureBuffer = signatureBytes.buffer.slice(
    signatureBytes.byteOffset,
    signatureBytes.byteOffset + signatureBytes.byteLength
  );

  // Derive the same wrapping key from passkey signature
  const wrappingKeyMaterial = await crypto.subtle.importKey(
    "raw",
    signatureBuffer,
    { name: "HKDF" },
    false,
    ["deriveKey"]
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
    ["decrypt"]
  );

  // Decode the wrapped key and IV
  const encryptedData = new Uint8Array(
    atob(wrappedKey)
      .split("")
      .map((c) => c.charCodeAt(0))
  );
  const ivBytes = new Uint8Array(
    atob(iv)
      .split("")
      .map((c) => c.charCodeAt(0))
  );

  // Decrypt using AES-GCM
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    wrappingKey,
    encryptedData
  );

  return new Uint8Array(decrypted);
}

// Types for passkey operations
export interface PasskeyCredential {
  id: string;
  publicKey: string;
  counter: number;
  created: number;
}

export interface AuthenticationResult {
  success: boolean;
  credential?: PasskeyCredential;
  error?: string;
}

/**
 * Register a new passkey for the user
 */
export async function registerPasskey(
  walletSignMessage: (message: string) => Promise<string>
): Promise<AuthenticationResult> {
  try {
    // First, ask user to sign the challenge with their wallet
    try {
      await walletSignMessage(FIXED_CHALLENGE);
    } catch (error) {
      return {
        success: false,
        error: "Wallet signature required for passkey creation",
      };
    }

    // Check if WebAuthn is supported
    if (!navigator.credentials || !navigator.credentials.create) {
      return {
        success: false,
        error: "WebAuthn is not supported in this browser",
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
          id: new TextEncoder().encode("wallet-user"),
          name: "wallet-user",
          displayName: "Wallet User",
        },
        pubKeyCredParams: [
          { alg: -7, type: "public-key" }, // ES256
          { alg: -257, type: "public-key" }, // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform", // Prefer platform authenticators (Touch ID, Face ID, etc.)
          userVerification: "required", // Require user verification
        },
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
      String.fromCharCode(...new Uint8Array(publicKey!))
    );

    const passkeyCredential: PasskeyCredential = {
      id: credential.id,
      publicKey: publicKeyString,
      counter: 0, // Initialize counter
      created: Date.now(),
    };

    // Store the credential
    const storedCredentials = getStoredCredentials();
    storedCredentials.push(passkeyCredential);
    localStorage.setItem("wallet-passkeys", JSON.stringify(storedCredentials));

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
 * Authenticate using a stored passkey
 */
export async function authenticateWithPasskey(): Promise<AuthenticationResult> {
  try {
    const storedCredentials = getStoredCredentials();

    if (storedCredentials.length === 0) {
      return {
        success: false,
        error: "No passkeys registered. Please register a passkey first.",
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
                .map((c) => c.charCodeAt(0))
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
      (assertion.response as AuthenticatorAssertionResponse).clientDataJSON
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

    return { success: true, credential: storedCredentials[0] };
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
 * Get all stored passkey credentials
 */
export function getStoredCredentials(): PasskeyCredential[] {
  try {
    const stored = localStorage.getItem("wallet-passkeys");
    return stored ? JSON.parse(stored) : [];
  } catch (error) {
    console.error("Failed to get stored credentials:", error);
    return [];
  }
}

/**
 * Clear all stored passkeys
 */
export function clearStoredCredentials(): void {
  localStorage.removeItem("wallet-passkeys");
}

/**
 * Delete a specific passkey by credential ID
 */
export function deletePasskey(credentialId: string): boolean {
  try {
    const storedCredentials = getStoredCredentials();
    const filteredCredentials = storedCredentials.filter(
      (cred) => cred.id !== credentialId
    );

    if (filteredCredentials.length < storedCredentials.length) {
      localStorage.setItem(
        "wallet-passkeys",
        JSON.stringify(filteredCredentials)
      );
      return true;
    }
    return false;
  } catch (error) {
    console.error("Failed to delete passkey:", error);
    return false;
  }
}

/**
 * Check if the user has any registered passkeys
 */
export function hasRegisteredPasskeys(): boolean {
  return getStoredCredentials().length > 0;
}
