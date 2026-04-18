import { DeletionPayload, CryptoError } from "./types";

function b64ToBytes(b64: string): Uint8Array {
  try {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  } catch (e) {
    throw new CryptoError(`Invalid base64: ${e instanceof Error ? e.message : String(e)}`, 'InvalidSignature');
  }
}

export async function verifyDeletionProof(
  payload: DeletionPayload,
  signatureB64: string,
  publicKeyB64: string
): Promise<void> {
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const sigBytes = b64ToBytes(signatureB64);
  const pubKeyBytes = b64ToBytes(publicKeyB64);

  const publicKey = await crypto.subtle.importKey(
    "raw",
    pubKeyBytes.buffer as ArrayBuffer,
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    sigBytes.buffer as ArrayBuffer,
    payloadBytes.buffer as ArrayBuffer
  );

  if (!valid) {
    throw new CryptoError('Invalid signature', 'InvalidSignature');
  }
}

export async function verifyDeletionProofJson(
  payloadJson: string,
  signatureB64: string,
  publicKeyB64: string
): Promise<void> {
  const payloadBytes = new TextEncoder().encode(payloadJson);
  const sigBytes = b64ToBytes(signatureB64);
  const pubKeyBytes = b64ToBytes(publicKeyB64);

  const publicKey = await crypto.subtle.importKey(
    "raw",
    pubKeyBytes.buffer as ArrayBuffer,
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    sigBytes.buffer as ArrayBuffer,
    payloadBytes.buffer as ArrayBuffer
  );

  if (!valid) {
    throw new CryptoError('Invalid signature', 'InvalidSignature');
  }
}
