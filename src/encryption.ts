/**
 * Encryption and decryption functions for VASTDISK SDK
 */

import { AES_GCM_ALGO, KEY_LENGTH, IV_LENGTH, CHUNK_SIZE, LENGTH_PREFIX } from "./constants";
import { arrayBufferToBase64Url, base64UrlToArrayBuffer, base64ToArrayBuffer, encodeLength, readLength, supportsCompressionStream } from "./utils";
import type { EncryptResult } from "./types";

const V2_MAGIC = new TextEncoder().encode("VAST"); // 4 bytes
const V2_VERSION = 2;
const V2_FILE_NONCE_LEN = 16;
// magic(4) + version(1) + flags(1) + reserved(2) + file_nonce(16) = 24 bytes
const V2_HEADER_LEN = 24;
const GCM_TAG_LEN = 16;

function isV2Ciphertext(bytes: Uint8Array): boolean {
  if (bytes.byteLength < V2_HEADER_LEN) return false;
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== V2_MAGIC[i]) return false;
  }
  return bytes[4] === V2_VERSION;
}

function makeV2Header(): Uint8Array {
  const header = new Uint8Array(V2_HEADER_LEN);
  header.set(V2_MAGIC, 0);
  header[4] = V2_VERSION;
  header[5] = 0; // flags (reserved)
  header[6] = 0; // reserved
  header[7] = 0; // reserved
  const nonce = window.crypto.getRandomValues(new Uint8Array(V2_FILE_NONCE_LEN));
  header.set(nonce, 8);
  return header;
}

function makeV2Aad(header: Uint8Array, chunkIndex: number): ArrayBuffer {
  // Use ArrayBuffer to avoid TS lib types that model SharedArrayBuffer in BufferSource.
  const aadBuf = new ArrayBuffer(V2_HEADER_LEN + 4);
  const aad = new Uint8Array(aadBuf);
  aad.set(header, 0);
  new DataView(aadBuf).setUint32(V2_HEADER_LEN, chunkIndex >>> 0, false);
  return aadBuf;
}

/**
 * Encrypt a file with AES-256-GCM, chunked at 1MB boundaries.
 * Optionally compress with gzip (CompressionStream) before encryption.
 *
 * Wire format v2:
 * - Header: "VAST" + version + nonce
 * - Chunks: [4-byte BE length][12-byte IV][AES-256-GCM(ciphertext+tag)]
 *
 * v2 uses AES-GCM AAD to bind chunk order to the file header, preventing
 * undetected reordering/truncation attacks by a malicious storage layer.
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
  const keyB64 = arrayBufferToBase64Url(rawKey);

  let dataStream: ReadableStream<Uint8Array>;
  if (compress && supportsCompressionStream()) {
    const cs = new CompressionStream("gzip");
    dataStream = file.stream().pipeThrough(cs) as ReadableStream<Uint8Array>;
  } else {
    dataStream = file.stream() as ReadableStream<Uint8Array>;
  }

  const parts: Blob[] = [];
  const header = makeV2Header();
  const headerBuf = header.buffer.slice(
    header.byteOffset,
    header.byteOffset + header.byteLength
  ) as ArrayBuffer;
  parts.push(new Blob([headerBuf]));
  const reader = dataStream.getReader();
  let buffer = new Uint8Array(0);
  let chunkIndex = 0;

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
      const aad = makeV2Aad(header, chunkIndex++);
      const encrypted = await window.crypto.subtle.encrypt(
        { name: AES_GCM_ALGO, iv, additionalData: aad },
        key,
        chunk
      );
      const encLen = encodeLength(IV_LENGTH + encrypted.byteLength);
      parts.push(new Blob([encLen.buffer as ArrayBuffer, iv.buffer as ArrayBuffer, encrypted]));
    }
  }

  if (buffer.length > 0) {
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const aad = makeV2Aad(header, chunkIndex++);
    const encrypted = await window.crypto.subtle.encrypt(
      { name: AES_GCM_ALGO, iv, additionalData: aad },
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
 * Key is the base64url-encoded raw AES key returned at encryption time.
 * @param decompress Whether to decompress the decrypted data using gzip.
 * @throws Error if decryption fails (e.g., wrong key, corrupted data)
 */
export async function decryptFile(ciphertext: Blob, keyB64: string, decompress: boolean = false): Promise<Blob> {
  let rawKey: ArrayBuffer;
  try {
    // Try base64url first
    rawKey = base64UrlToArrayBuffer(keyB64);
  } catch (e) {
    try {
      // Fall back to standard base64
      rawKey = base64ToArrayBuffer(keyB64);
    } catch (e2) {
      throw new Error("Invalid key format: key must be a valid base64 or base64url string");
    }
  }

  if (rawKey.byteLength !== KEY_LENGTH / 8) {
    throw new Error(`Invalid key length: expected ${KEY_LENGTH / 8} bytes, got ${rawKey.byteLength}`);
  }

  let key: CryptoKey;
  try {
    key = await window.crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: AES_GCM_ALGO, length: KEY_LENGTH },
      false,
      ["decrypt"]
    );
  } catch (e) {
    throw new Error("Failed to import decryption key");
  }

  const buffer = new Uint8Array(await ciphertext.arrayBuffer());
  const chunks: Blob[] = [];
  let offset = 0;
  let chunkIndex = 0;
  let v2Header: Uint8Array | null = null;

  if (isV2Ciphertext(buffer)) {
    v2Header = buffer.slice(0, V2_HEADER_LEN);
    offset = V2_HEADER_LEN;
  }

  while (offset < buffer.byteLength) {
    if (offset + LENGTH_PREFIX > buffer.byteLength) {
      throw new Error("Corrupt ciphertext: truncated length prefix");
    }

    const chunkLen = readLength(buffer, offset);
    offset += LENGTH_PREFIX;

    if (chunkLen < IV_LENGTH + GCM_TAG_LEN) {
      throw new Error("Corrupt ciphertext: invalid chunk length");
    }

    if (offset + chunkLen > buffer.byteLength) {
      throw new Error("Corrupt ciphertext: truncated chunk data");
    }

    const iv = buffer.slice(offset, offset + IV_LENGTH);
    offset += IV_LENGTH;

    const encDataLen = chunkLen - IV_LENGTH;
    const encData = buffer.slice(offset, offset + encDataLen);
    offset += encDataLen;

    let decrypted: ArrayBuffer;
    try {
      const additionalData = v2Header ? makeV2Aad(v2Header, chunkIndex) : undefined;
      decrypted = await window.crypto.subtle.decrypt(
        additionalData ? { name: AES_GCM_ALGO, iv, additionalData } : { name: AES_GCM_ALGO, iv },
        key,
        encData
      );
    } catch (e) {
      // OperationError is thrown by Web Crypto API when GCM authentication fails
      if (e instanceof Error && e.name === "OperationError") {
        throw new Error("Incorrect decryption key. The file cannot be decrypted with the provided key.");
      }
      throw new Error(`Decryption failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    chunks.push(new Blob([decrypted]));
    chunkIndex++;
  }

  const decryptedBlob = new Blob(chunks);
  
  // Decompress the decrypted data if the file was compressed
  if (decompress && supportsCompressionStream()) {
    try {
      const decompressedStream = decryptedBlob.stream().pipeThrough(new DecompressionStream("gzip"));
      return await new Response(decompressedStream).blob();
    } catch (e) {
      throw new Error("Decompression failed: data is not valid gzip (wrong key, corrupt file, or incorrect compression flag)");
    }
  }
  
  return decryptedBlob;
}
