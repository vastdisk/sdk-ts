/**
 * Internal utility functions for VASTDISK SDK
 */

import { LENGTH_PREFIX } from "./constants";

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const chars = new Array(bytes.byteLength);
  for (let i = 0; i < bytes.byteLength; i++) {
    chars[i] = bytes[i];
  }
  return btoa(String.fromCharCode.apply(null, chars));
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const chars = atob(base64);
  const bytes = new Uint8Array(chars.length);
  for (let i = 0; i < chars.length; i++) {
    bytes[i] = chars.charCodeAt(i);
  }
  return bytes.buffer;
}

export function encodeLength(n: number): Uint8Array {
  const buf = new Uint8Array(LENGTH_PREFIX);
  new DataView(buf.buffer).setUint32(0, n, false);
  return buf;
}

export function readLength(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset + offset, LENGTH_PREFIX).getUint32(0, false);
}

export function supportsCompressionStream(): boolean {
  return typeof CompressionStream !== "undefined";
}

export function toHex(bytes: Uint8Array): string {
  const hex = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    hex[i] = bytes[i].toString(16).padStart(2, "0");
  }
  return hex.join("");
}
