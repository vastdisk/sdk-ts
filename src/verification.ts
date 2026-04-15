/**
 * Deletion proof verification for VASTDISK SDK
 */

import type { DeletionPayload } from "./types";

/**
 * Verify an Ed25519 deletion proof signature using Web Crypto API.
 *
 * @param payload  - The deletion payload object (will be JSON-serialized for verification)
 * @param signatureB64 - Base64-encoded Ed25519 signature
 * @param publicKeyB64 - Base64-encoded Ed25519 public key
 * @returns true if the signature is valid
 */
export async function verifyDeletionProof(
  payload: DeletionPayload,
  signatureB64: string,
  publicKeyB64: string
): Promise<boolean> {
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const sigBytes = Uint8Array.from(atob(signatureB64), (c) => c.charCodeAt(0));
  const pubKeyBytes = Uint8Array.from(atob(publicKeyB64), (c) => c.charCodeAt(0));

  const publicKey = await crypto.subtle.importKey(
    "raw",
    pubKeyBytes,
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  return crypto.subtle.verify({ name: "Ed25519" }, publicKey, sigBytes, payloadBytes);
}
