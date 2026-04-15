/**
 * Hashing functions for VASTDISK SDK
 */

import { blake3 } from "@noble/hashes/blake3";
import { toHex } from "./utils";

/**
 * Hash a ciphertext blob with SHA-256 using Web Crypto API.
 * Note: the server uses BLAKE3 for hashing. Use hashCiphertextBlake3()
 * to produce a hash that matches the server-side value for proof verification.
 */
export async function hashCiphertext(ciphertext: Blob): Promise<string> {
  const buffer = new Uint8Array(await ciphertext.arrayBuffer());
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return toHex(new Uint8Array(hashBuffer));
}

/**
 * Hash a ciphertext blob with BLAKE3 - matches the server-side hash
 * used in deletion proof payloads. This is the recommended hash function
 * for verifying deletion receipts.
 */
export function hashCiphertextBlake3(ciphertext: Blob): Promise<string> {
  return ciphertext.arrayBuffer().then((buf) => {
    const hash = blake3(new Uint8Array(buf));
    return toHex(hash);
  });
}
