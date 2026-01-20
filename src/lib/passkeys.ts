// Fixed challenge for development - in production, this should be generated server-side
const FIXED_CHALLENGE = "wallet-passkey-challenge-2024";
//const KEY_FROM_WALLET_CHALLENGE = "Signing this message proves you own the wallet: " + ". Generates a unique signature. This signature is used to sign and encrypt/decrypt data. You must sign this message ONLY on https://wallet.inbytes.xyz, otherwise you are being phished." ;
// Pre-computed base64url encoded challenge for verification
const EXPECTED_CHALLENGE_B64URL = "d2FsbGV0LXBhc3NrZXktY2hhbGxlbmdlLTIwMjQ";

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
  username: string
): Promise<AuthenticationResult> {
  try {
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
          id: new TextEncoder().encode(username),
          name: username,
          displayName: username,
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
            id: Uint8Array.from(atob(base64UrlToBase64(credentialId)), (c) =>
              c.charCodeAt(0)
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
    const authData = new Uint8Array(
      (assertion.response as AuthenticatorAssertionResponse).authenticatorData
    );
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
