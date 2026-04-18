/**
 * Deletion proof verification for VASTDISK SDK
 */

import type { DeletionPayload } from "./types";

function b64ToBytes(b64: string): Uint8Array {
  try {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  } catch (e) {
    throw new Error(`Invalid base64: ${e instanceof Error ? e.message : String(e)}`);
  }
}

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
  const sigBytes = b64ToBytes(signatureB64);
  const pubKeyBytes = b64ToBytes(publicKeyB64);

  const publicKey = await crypto.subtle.importKey(
    "raw",
    pubKeyBytes as BufferSource,
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  return crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    sigBytes as BufferSource,
    payloadBytes as BufferSource
  );
}

/**
 * Verify a deletion proof against an exact JSON payload string.
 *
 * Prefer this when the server provides `payload_json`, as it avoids any
 * serialization/canonicalization ambiguity across languages.
 */
export async function verifyDeletionProofJson(
  payloadJson: string,
  signatureB64: string,
  publicKeyB64: string
): Promise<boolean> {
  const payloadBytes = new TextEncoder().encode(payloadJson);
  const sigBytes = b64ToBytes(signatureB64);
  const pubKeyBytes = b64ToBytes(publicKeyB64);

  const publicKey = await crypto.subtle.importKey(
    "raw",
    pubKeyBytes as BufferSource,
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  return crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    sigBytes as BufferSource,
    payloadBytes as BufferSource
  );
}
