import { blake3 } from "@noble/hashes/blake3";
import { toHex } from "./utils";
import { HashAlgorithm } from "./types";

export async function hash(data: Uint8Array, algo: HashAlgorithm): Promise<string> {
  if (algo === HashAlgorithm.Blake3) {
    const hash = blake3(data);
    return toHex(hash);
  } else if (algo === HashAlgorithm.Sha256) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
    return toHex(new Uint8Array(hashBuffer));
  }
  throw new Error("Unknown hash algorithm");
}

export async function hashCiphertext(ciphertext: Blob): Promise<string> {
  const buffer = new Uint8Array(await ciphertext.arrayBuffer());
  return hash(buffer, HashAlgorithm.Sha256);
}

export async function hashCiphertextBlake3(ciphertext: Blob): Promise<string> {
  const buffer = new Uint8Array(await ciphertext.arrayBuffer());
  return hash(buffer, HashAlgorithm.Blake3);
}

export async function hashSha256(data: Uint8Array): Promise<string> {
  return hash(data, HashAlgorithm.Sha256);
}

export async function hashBlake3(data: Uint8Array): Promise<string> {
  return hash(data, HashAlgorithm.Blake3);
}
