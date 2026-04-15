/**
 * Encryption and decryption functions for VASTDISK SDK
 */

import { AES_GCM_ALGO, KEY_LENGTH, IV_LENGTH, CHUNK_SIZE, LENGTH_PREFIX } from "./constants";
import { arrayBufferToBase64, base64ToArrayBuffer, encodeLength, readLength, supportsCompressionStream } from "./utils";
import type { EncryptResult } from "./types";

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
 * @param decompress Whether to decompress the decrypted data using gzip.
 */
export async function decryptFile(ciphertext: Blob, keyB64: string, decompress: boolean = false): Promise<Blob> {
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

  const decryptedBlob = new Blob(chunks);
  
  // Decompress the decrypted data if the file was compressed
  if (decompress && supportsCompressionStream()) {
    try {
      const decompressedStream = decryptedBlob.stream().pipeThrough(new DecompressionStream("gzip"));
      return await new Response(decompressedStream).blob();
    } catch (e) {
      // If decompression fails, return the decrypted blob as-is
      console.warn("Decompression failed, returning decrypted data:", e);
      return decryptedBlob;
    }
  }
  
  return decryptedBlob;
}

