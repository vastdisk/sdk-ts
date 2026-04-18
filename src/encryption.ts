import { AES_GCM_ALGO, KEY_LENGTH, IV_LENGTH, CHUNK_SIZE, LENGTH_PREFIX } from "./constants";
import { arrayBufferToBase64Url, base64UrlToArrayBuffer, base64ToArrayBuffer, encodeLength, readLength, supportsCompressionStream } from "./utils";
import type { EncryptResult, EncryptOptions, CryptoError } from "./types";
import { defaultEncryptOptions } from "./types";

const V2_MAGIC = new TextEncoder().encode("VAST");
const V2_VERSION = 2;
const V2_FILE_NONCE_LEN = 16;
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
  header[5] = 0;
  header[6] = 0;
  header[7] = 0;
  const nonce = window.crypto.getRandomValues(new Uint8Array(V2_FILE_NONCE_LEN));
  header.set(nonce, 8);
  return header;
}

function makeV2Aad(header: Uint8Array, chunkIndex: number): ArrayBuffer {
  const aadBuf = new ArrayBuffer(V2_HEADER_LEN + 4);
  const aad = new Uint8Array(aadBuf);
  aad.set(header, 0);
  new DataView(aadBuf).setUint32(V2_HEADER_LEN, chunkIndex >>> 0, false);
  return aadBuf;
}

export async function encryptFile(
  file: File,
  compress: boolean = false
): Promise<EncryptResult> {
  return encryptFileWithOpts(file, { ...defaultEncryptOptions, compress });
}

export async function encryptFileWithOpts(
  file: File,
  opts: EncryptOptions
): Promise<EncryptResult> {
  const key = await window.crypto.subtle.generateKey(
    { name: AES_GCM_ALGO, length: KEY_LENGTH },
    true,
    ["encrypt", "decrypt"]
  );

  const rawKey = await window.crypto.subtle.exportKey("raw", key);
  const keyB64 = arrayBufferToBase64Url(rawKey);

  let dataStream: ReadableStream<Uint8Array>;
  if (opts.compress && supportsCompressionStream()) {
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

    while (buffer.length >= opts.chunkSize) {
      const chunk = buffer.slice(0, opts.chunkSize);
      buffer = buffer.slice(opts.chunkSize);

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

export async function decryptFile(ciphertext: Blob, keyB64: string, decompress: boolean = false): Promise<Blob> {
  let rawKey: ArrayBuffer;
  try {
    rawKey = base64UrlToArrayBuffer(keyB64);
  } catch (e) {
    try {
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
      if (e instanceof Error && e.name === "OperationError") {
        throw new Error("Incorrect decryption key. The file cannot be decrypted with the provided key.");
      }
      throw new Error(`Decryption failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    chunks.push(new Blob([decrypted]));
    chunkIndex++;
  }

  const decryptedBlob = new Blob(chunks);
  
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

export async function encryptData(data: Uint8Array, opts: EncryptOptions = defaultEncryptOptions): Promise<EncryptResult> {
  const key = await window.crypto.subtle.generateKey(
    { name: AES_GCM_ALGO, length: KEY_LENGTH },
    true,
    ["encrypt", "decrypt"]
  );

  const rawKey = await window.crypto.subtle.exportKey("raw", key);
  const keyB64 = arrayBufferToBase64Url(rawKey);

  const parts: Blob[] = [];
  const header = makeV2Header();
  const headerBuf = header.buffer.slice(
    header.byteOffset,
    header.byteOffset + header.byteLength
  ) as ArrayBuffer;
  parts.push(new Blob([headerBuf]));
  let chunkIndex = 0;

  for (let offset = 0; offset < data.length; offset += opts.chunkSize) {
    const chunk = data.slice(offset, Math.min(offset + opts.chunkSize, data.length));

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

  return { ciphertext: new Blob(parts), key: keyB64 };
}

export async function decryptData(ciphertext: Uint8Array, keyB64: string): Promise<Uint8Array> {
  const blob = new Blob([ciphertext.buffer as ArrayBuffer]);
  const decryptedBlob = await decryptFile(blob, keyB64);
  return new Uint8Array(await decryptedBlob.arrayBuffer());
}
