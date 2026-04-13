/**
 * @vastdisk/sdk-ts — Client-side crypto SDK for VASTDISK
 *
 * Encryption uses the browser-native Web Crypto API.
 * BLAKE3 hashing via @noble/hashes (zero native deps, tree-shakeable).
 * Licensed under AGPLv3 — see LICENSE for details.
 */

// ─── Constants ────────────────────────────────────────────────────────────────

const AES_GCM_ALGO = "AES-GCM";
const KEY_LENGTH = 256;
const IV_LENGTH = 12;
const CHUNK_SIZE = 1024 * 1024; // 1MB chunks
const LENGTH_PREFIX = 4; // uint32 BE

// ─── Internal helpers ─────────────────────────────────────────────────────────

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function encodeLength(n: number): Uint8Array {
  const buf = new Uint8Array(LENGTH_PREFIX);
  new DataView(buf.buffer).setUint32(0, n, false);
  return buf;
}

function readLength(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset + offset, LENGTH_PREFIX).getUint32(0, false);
}

function supportsCompressionStream(): boolean {
  return typeof CompressionStream !== "undefined";
}

// ─── BLAKE3 (via @noble/hashes) ────────────────────────────────────────────────

import { blake3 } from "@noble/hashes/blake3";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── Public types ──────────────────────────────────────────────────────────────

export interface DeletionPayload {
  file_id: string;
  file_hash: string;
  deleted_at: string;
  deletion_reason: string;
}

export interface SignedProof {
  payload: DeletionPayload;
  signature_b64: string;
  public_key_b64: string;
}

export interface EncryptResult {
  ciphertext: Blob;
  key: string;
}

// ─── Public API ───────────────────────────────────────────────────────────────

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
 * Hash a ciphertext blob with BLAKE3 — matches the server-side hash
 * used in deletion proof payloads. This is the recommended hash function
 * for verifying deletion receipts.
 */
export function hashCiphertextBlake3(ciphertext: Blob): Promise<string> {
  return ciphertext.arrayBuffer().then((buf) => {
    const hash = blake3(new Uint8Array(buf));
    return toHex(hash);
  });
}

/**
 * Encrypt a file with AES-256-GCM, chunked at 1MB boundaries.
 * Optionally compress with gzip (CompressionStream) before encryption.
 *
 * Wire format per chunk: [4-byte BE length][12-byte IV][encrypted data]
 */
export async function encryptFile(
  file: File,
  compress: boolean = false
): Promise<EncryptResult> {
  const key = await window.crypto.subtle.generateKey(
    { name: AES_GCM_ALGO, length: KEY_LENGTH },
    true,
    ["encrypt", "decrypt"]
  );

  const rawKey = await window.crypto.subtle.exportKey("raw", key);
  const keyB64 = arrayBufferToBase64(rawKey);

  let dataStream: ReadableStream<Uint8Array>;
  if (compress && supportsCompressionStream()) {
    const cs = new CompressionStream("gzip");
    dataStream = file.stream().pipeThrough(cs) as ReadableStream<Uint8Array>;
  } else {
    dataStream = file.stream() as ReadableStream<Uint8Array>;
  }

  const parts: Blob[] = [];
  const reader = dataStream.getReader();
  let buffer = new Uint8Array(0);

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    const newBuf = new Uint8Array(buffer.length + value.length);
    newBuf.set(buffer);
    newBuf.set(value, buffer.length);
    buffer = newBuf;

    while (buffer.length >= CHUNK_SIZE) {
      const chunk = buffer.slice(0, CHUNK_SIZE);
      buffer = buffer.slice(CHUNK_SIZE);

      const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
      const encrypted = await window.crypto.subtle.encrypt(
        { name: AES_GCM_ALGO, iv },
        key,
        chunk
      );
      const encLen = encodeLength(IV_LENGTH + encrypted.byteLength);
      parts.push(new Blob([encLen.buffer as ArrayBuffer, iv.buffer as ArrayBuffer, encrypted]));
    }
  }

  if (buffer.length > 0) {
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encrypted = await window.crypto.subtle.encrypt(
      { name: AES_GCM_ALGO, iv },
      key,
      buffer
    );
    const encLen = encodeLength(IV_LENGTH + encrypted.byteLength);
    parts.push(new Blob([encLen.buffer as ArrayBuffer, iv.buffer as ArrayBuffer, encrypted]));
  }

  return { ciphertext: new Blob(parts), key: keyB64 };
}

/**
 * Decrypt a ciphertext blob produced by encryptFile().
 * Key is the base64-encoded raw AES key returned at encryption time.
 */
export async function decryptFile(ciphertext: Blob, keyB64: string): Promise<Blob> {
  const rawKey = base64ToArrayBuffer(keyB64);
  const key = await window.crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: AES_GCM_ALGO, length: KEY_LENGTH },
    false,
    ["decrypt"]
  );

  const buffer = new Uint8Array(await ciphertext.arrayBuffer());
  const chunks: Blob[] = [];
  let offset = 0;

  while (offset < buffer.byteLength) {
    const chunkLen = readLength(buffer, offset);
    offset += LENGTH_PREFIX;

    const iv = buffer.slice(offset, offset + IV_LENGTH);
    offset += IV_LENGTH;

    const encDataLen = chunkLen - IV_LENGTH;
    const encData = buffer.slice(offset, offset + encDataLen);
    offset += encDataLen;

    const decrypted = await window.crypto.subtle.decrypt(
      { name: AES_GCM_ALGO, iv },
      key,
      encData
    );
    chunks.push(new Blob([decrypted]));
  }

  return new Blob(chunks);
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

/**
 * Determine if a file should be compressed by default.
 * Returns true for text-like files >1MB when CompressionStream is available.
 */
export function shouldCompressByDefault(file: File): boolean {
  if (!supportsCompressionStream()) return false;
  if (file.size < 1024 * 1024) return false;
  const textExtensions = [
    ".txt", ".md", ".csv", ".json", ".xml", ".html", ".css", ".js", ".ts",
    ".tsx", ".jsx", ".py", ".rs", ".go", ".java", ".c", ".cpp", ".h",
    ".sh", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".log",
    ".sql", ".env", ".svg",
  ];
  const ext = file.name.toLowerCase().slice(file.name.lastIndexOf("."));
  return textExtensions.includes(ext);
}
