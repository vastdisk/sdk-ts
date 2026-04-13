# @vastdisk/sdk-ts

Client-side crypto SDK for [VASTDISK](https://vastdisk.com). Licensed under **AGPLv3** for full transparency and auditability.

## What It Does

- **AES-256-GCM** chunked encryption/decryption (1 MB chunks, random IV per chunk)
- **BLAKE3** ciphertext hashing (matches server-side hash for proof verification)
- **SHA-256** ciphertext hashing (legacy, for fingerprint comparison)
- **Ed25519** deletion-proof signature verification
- **Gzip compression** via `CompressionStream` (optional, browser-native)

Encryption uses the browser-native **Web Crypto API**. BLAKE3 uses **@noble/hashes** (pure JS, tree-shakeable, zero native deps).

## Install

```bash
npm install @vastdisk/sdk-ts
```

## Usage

```typescript
import {
  encryptFile,
  decryptFile,
  hashCiphertextBlake3,
  hashCiphertext,
  verifyDeletionProof,
  shouldCompressByDefault,
} from "@vastdisk/sdk-ts";

// Encrypt
const { ciphertext, key } = await encryptFile(file, true); // true = compress

// Decrypt
const plaintext = await decryptFile(ciphertext, key);

// BLAKE3 hash (matches server — use this for deletion proof verification)
const hash = await hashCiphertextBlake3(ciphertext);

// SHA-256 hash (legacy fingerprint)
const shaHash = await hashCiphertext(ciphertext);

// Verify deletion proof
const valid = await verifyDeletionProof(payload, signatureB64, publicKeyB64);

// Auto-detect compression
if (shouldCompressByDefault(file)) { /* enable compression */ }
```

## Wire Format

Each encrypted chunk: `[4-byte BE length][12-byte IV][AES-256-GCM ciphertext]`

Multiple chunks are concatenated into a single Blob.

## License

AGPLv3 — see [LICENSE](./LICENSE). Crypto code is open for audit.