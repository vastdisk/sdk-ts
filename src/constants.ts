/**
 * Cryptographic constants for VASTDISK SDK
 */

export const AES_GCM_ALGO = "AES-GCM";
export const KEY_LENGTH = 256;
export const IV_LENGTH = 12;
export const CHUNK_SIZE = 1024 * 1024; // 1MB chunks
export const LENGTH_PREFIX = 4; // uint32 BE
