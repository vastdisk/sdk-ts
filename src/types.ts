/**
 * TypeScript types for VASTDISK SDK
 */

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
