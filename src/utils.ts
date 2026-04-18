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

/**
 * Convert ArrayBuffer to base64url string (URL-safe base64)
 * Replaces '+' with '-', '/' with '_', and removes trailing '='
 */
export function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const base64 = arrayBufferToBase64(buffer);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  try {
    const chars = atob(base64);
    const bytes = new Uint8Array(chars.length);
    for (let i = 0; i < chars.length; i++) {
      bytes[i] = chars.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (e) {
    throw new Error(`Invalid base64 string: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * Convert base64url string to ArrayBuffer
 * Replaces '-' with '+', '_' with '/', and adds padding if needed
 */
export function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  try {
    // Convert base64url to standard base64
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    while (base64.length % 4) {
      base64 += '=';
    }
    return base64ToArrayBuffer(base64);
  } catch (e) {
    throw new Error(`Invalid base64url string: ${e instanceof Error ? e.message : String(e)}`);
  }
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
