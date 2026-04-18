export interface DeletionPayload {
  file_id: string;
  file_hash: string;
  deleted_at: string;
  deletion_reason: string;
}

export class CryptoError extends Error {
  constructor(
    message: string,
    public code: 'InvalidKey' | 'InvalidCiphertext' | 'EncryptionFailed' | 'DecryptionFailed' | 'InvalidSignature' | 'IoError'
  ) {
    super(message);
    this.name = 'CryptoError';
  }
}

export type CryptoResult<T> = Promise<T>;

export interface EncryptResult {
  ciphertext: Blob;
  key: string;
}

export interface EncryptOptions {
  chunkSize: number;
  compress: boolean;
}

export const defaultEncryptOptions: EncryptOptions = {
  chunkSize: 1024 * 1024,
  compress: false,
};

export enum HashAlgorithm {
  Blake3 = 'Blake3',
  Sha256 = 'Sha256',
}

export enum EncryptionAlgorithm {
  Aes256Gcm = 'Aes256Gcm',
  XChaCha20Poly1305 = 'XChaCha20Poly1305',
}
