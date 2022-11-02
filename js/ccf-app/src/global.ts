// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * This module describes the global {@linkcode ccf} variable.
 * Direct access of this module or the {@linkcode ccf} variable is
 * typically not needed as all of its functionality is exposed
 * via other, often more high-level, modules.
 *
 * Accessing the {@linkcode ccf} global in a type-safe way is done
 * as follows:
 *
 * ```
 * import { ccf } from '@microsoft/ccf-app/global.js';
 * ```
 *
 * @module
 */

// The global ccf variable and associated types are exported
// as a regular module instead of using an ambient namespace
// in a .d.ts definition file.
// This avoids polluting the global namespace.

export const ccf: CCF = (<any>globalThis).ccf;

// This should eventually cover all JSON-compatible values.
// There are attempts at https://github.com/microsoft/TypeScript/issues/1897
// to create such a type but it needs further refinement.
export type JsonCompatible<T> = any;

/**
 * A map in the Key Value Store.
 *
 * `KVMap` is modelled after JavaScript's `Map` object,
 * except that keys and values must be of type `ArrayBuffer`
 * and no guarantees on iteration order are provided.
 */
export interface KvMap {
  has(key: ArrayBuffer): boolean;
  get(key: ArrayBuffer): ArrayBuffer | undefined;
  getVersionOfPreviousWrite(key: ArrayBuffer): number | undefined;
  set(key: ArrayBuffer, value: ArrayBuffer): KvMap;
  delete(key: ArrayBuffer): void;
  clear(): void;
  forEach(
    callback: (value: ArrayBuffer, key: ArrayBuffer, kvmap: KvMap) => void
  ): void;
  size: number;
}

/**
 * @inheritDoc CCF.kv
 */
export type KvMaps = { [key: string]: KvMap };

export interface ProofElement {
  /**
   * Hex-encoded Merkle tree element hash.
   */
  left?: string;

  /**
   * Hex-encoded Merkle tree element hash.
   */
  right?: string;
}

export interface LeafComponents {
  /**
   * Hex-encoded hash of transaction's write set.
   */
  write_set_digest: string;

  /**
   * Raw bytes of commit evidence.
   */
  commit_evidence?: string;

  /**
   * Hex-encoded hash of transaction's claims.
   */
  claims_digest?: string;
}

/**
 * @inheritDoc Receipt.proof
 */
export type Proof = ProofElement[];

export interface Receipt {
  /**
   * Base64-encoded signature of the Merkle tree root hash.
   */
  signature: string;

  /**
   * Certificate of the node that signed the Merkle tree root hash.
   */
  cert: string;

  /**
   * Merkle tree inclusion proof as an array of ``ProofElement`` objects.
   */
  proof: Proof;

  /**
   * Hex-encoded Merkle tree leaf hash, for pre-2.x transactions.
   */
  leaf?: string;

  /**
   * Components of Merkle tree leaf hash, which digest together to replace leaf.
   */
  leaf_components?: LeafComponents;

  /**
   * ID of the node that signed the Merkle tree root hash.
   */
  node_id: string;
}

/**
 * State associated with a specific historic transaction.
 */
export interface HistoricalState {
  /**
   * The ID of the transaction, formatted as '<view>.<seqno>' string.
   */
  transactionId: string;

  /**
   * The receipt for the historic transaction.
   */
  receipt: Receipt;

  /**
   * An object that provides access to the maps of the Key-Value Store
   * associated with the historic transaction.
   * Fields are map names and values are {@linkcode KvMap} objects.
   */
  kv: KvMaps;
}

export interface TransactionId {
  view: number;
  seqno: number;
}

export type TransactionStatus = "Committed" | "Invalid" | "Pending" | "Unknown";

/**
 * [RSA-OAEP](https://datatracker.ietf.org/doc/html/rfc8017)
 * key wrapping with SHA-256 as digest function.
 *
 * The `key` argument of {@link CCF.wrapKey} can be of
 * arbitrary content up to the maximum size supported
 * by the wrapping algorithm.
 * The `wrappingKey` argument must be a PEM-encoded RSA public key.
 */
export interface RsaOaepParams {
  name: "RSA-OAEP";

  /**
   * A label to be associated with the wrapped key.
   */
  label?: ArrayBuffer;
}

/**
 * [AES key wrapping with padding](https://tools.ietf.org/html/rfc5649).
 *
 * The `key` argument of {@link CCF.wrapKey} can be of
 * arbitrary content.
 * The `wrappingKey` argument must be an AES key.
 */
export interface AesKwpParams {
  name: "AES-KWP";
}

/**
 * [RSA AES key wrapping](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc370634387)
 * with SHA-256 as digest function.
 *
 * The `key` argument of {@link CCF.wrapKey} can be of
 * arbitrary content.
 * The `wrappingKey` argument must be a PEM-encoded RSA public key.
 */
export interface RsaOaepAesKwpParams {
  name: "RSA-OAEP-AES-KWP";

  /**
   * Size of the temporary AES key in bits.
   */
  aesKeySize: number;

  /**
   * A label to be associated with the wrapped key.
   */
  label?: ArrayBuffer;
}

export type WrapAlgoParams = RsaOaepParams | AesKwpParams | RsaOaepAesKwpParams;

export interface CryptoKeyPair {
  /**
   * Private key in PEM encoding.
   */
  privateKey: string;

  /**
   * Public key in PEM encoding.
   */
  publicKey: string;
}

export type AlgorithmName = "RSASSA-PKCS1-v1_5" | "ECDSA" | "EdDSA";

export type DigestAlgorithm = "SHA-256";

export interface SigningAlgorithm {
  name: AlgorithmName;

  /**
   * Digest algorithm. It's necessary for "RSASSA-PKCS1-v1_5" and "ECDSA"
   */
  hash?: DigestAlgorithm;
}

/**
 * Interfaces for JSON Web Key objects, as per [RFC7517](https://www.rfc-editor.org/rfc/rfc751).
 */
export interface JsonWebKey {
  /**
   * Key type.
   */
  kty: string;

  /**
   * Key ID.
   */
  kid?: string;
}

export interface JsonWebKeyECPublic extends JsonWebKey {
  /**
   * Elliptic curve identifier.
   */
  crv: string;

  /**
   * Base64url-encoded x coordinate.
   */
  x: string;

  /**
   * Base64url-encoded y coordinate.
   */
  y: string;
}

export interface JsonWebKeyECPrivate extends JsonWebKeyECPublic {
  /**
   * Base64url-encoded d coordinate.
   */
  d: string;
}

export interface JsonWebKeyRSAPublic extends JsonWebKey {
  /**
   * Base64url-encoded modulus.
   */
  n: string;

  /**
   * Base64url-encoded exponent.
   */
  e: string;
}

export interface JsonWebKeyRSAPrivate extends JsonWebKeyRSAPublic {
  /**
   * Private exponent.
   */
  d: string;

  /**
   * Additional exponents.
   */
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
}

export interface CCFCrypto {
  /**
   * Generate a signature.
   *
   * @param algorithm Signing algorithm and parameters
   * @param key A PEM-encoded private key
   * @param plaintext Input data that will be signed
   * @throws Will throw an error if the key is not compatible with the
   *  signing algorithm or if an unknown algorithm is used.
   */
  sign(
    algorithm: SigningAlgorithm,
    key: string,
    plaintext: ArrayBuffer
  ): ArrayBuffer;

  /**
   * Returns whether digital signature is valid.
   *
   * @param algorithm Signing algorithm and parameters
   * @param key A PEM-encoded public key or X.509 certificate
   * @param signature Signature to verify
   * @param data Data that was signed
   * @throws Will throw an error if the key is not compatible with the
   *  signing algorithm or if an unknown algorithm is used.
   */
  verifySignature(
    algorithm: SigningAlgorithm,
    key: string,
    signature: ArrayBuffer,
    data: ArrayBuffer
  ): boolean;

  /**
   * Generate an AES key.
   *
   * @param size The length in bits of the key to generate. 128, 192, or 256.
   */
  generateAesKey(size: number): ArrayBuffer;

  /**
   * Generate an RSA key pair.
   *
   * @param size The length in bits of the RSA modulus. Minimum: 2048.
   * @param exponent The public exponent. Default: 65537.
   */
  generateRsaKeyPair(size: number, exponent?: number): CryptoKeyPair;

  /**
   * Generate an ECDSA key pair.
   *
   * @param curve The name of the curve, one of "secp256r1", "secp256k1", "secp384r1".
   */
  generateEcdsaKeyPair(curve: string): CryptoKeyPair;

  /**
   * Generate an EdDSA key pair.
   *
   * @param curve The name of the curve. Currently only "curve25519" is supported.
   */
  generateEddsaKeyPair(curve: string): CryptoKeyPair;

  /**
   * Wraps a key using a wrapping key.
   *
   * Constraints on the `key` and `wrappingKey` parameters depend
   * on the wrapping algorithm that is used (`wrapAlgo`).
   */
  wrapKey(
    key: ArrayBuffer,
    wrappingKey: ArrayBuffer,
    wrapAlgo: WrapAlgoParams
  ): ArrayBuffer;

  /**
   * Generate a digest (hash) of the given data.
   */
  digest(algorithm: DigestAlgorithm, data: ArrayBuffer): ArrayBuffer;

  /**
   * Returns whether a string is a PEM-encoded bundle of X.509 certificates.
   *
   * A bundle consists of one or more certificates.
   * Certificates in the bundle do not have to be related to each other.
   * Validation is only syntactical, properties like validity dates are not evaluated.
   */
  isValidX509CertBundle(pem: string): boolean;

  /**
   * Returns whether a certificate chain is valid given a set of trusted certificates.
   * The chain and trusted certificates are PEM-encoded bundles of X.509 certificates.
   */
  isValidX509CertChain(chain: string, trusted: string): boolean;

  /**
   * Converts an elliptic curve public key as PEM to JSON Web Key (JWK) object.
   *
   * @param pem Elliptic curve public key as PEM
   * @param kid Key identifier (optional)
   */
  pubPemToJwk(pem: string, kid?: string): JsonWebKeyECPublic;

  /**
   * Converts an elliptic curve private key as PEM to JSON Web Key (JWK) object.
   *
   * @param pem Elliptic curve private key as PEM
   * @param kid Key identifier (optional)
   */
  pemToJwk(pem: string, kid?: string): JsonWebKeyECPrivate;

  /**
   * Converts an RSA public key as PEM to JSON Web Key (JWK) object.
   *
   * @param pem RSA public key as PEM
   * @param kid Key identifier (optional)
   */
  pubRsaPemToJwk(pem: string, kid?: string): JsonWebKeyRSAPublic;

  /**
   * Converts an RSA private key as PEM to JSON Web Key (JWK) object.
   *
   * @param pem RSA private key as PEM
   * @param kid Key identifier (optional)
   */
  rsaPemToJwk(pem: string, kid?: string): JsonWebKeyRSAPrivate;
}

export interface CCFRpc {
  /**
   * Set whether KV writes should be applied even if the response status is not 2xx.
   * The default is `false`.
   */
  setApplyWrites(force: boolean): void;

  /**
   * Set a claims digest to be associated with the transaction if it succeeds. This
   * digest can later be accessed from the receipt, and expanded into a full claim.
   *
   * The `digest` argument must be a sha-256 ArrayBuffer, eg. produced by {@link global!CCF.digest}.
   */
  setClaimsDigest(digest: ArrayBuffer): void;
}

export interface CCFConsensus {
  /**
   * Get the ID of latest transaction known to be committed.
   */
  getLastCommittedTxId(): TransactionId;

  /**
   * Get the status of a transaction by ID, provided as a view+seqno pair.
   *
   * Note that this value is the node's local understanding of the status
   * of that transaction in the network at call time. For a given TxID, the
   * initial status is always UNKNOWN, and eventually becomes COMMITTED or
   * INVALID. See the documentation section titled "Verifying Transactions"
   * for more detail.
   *
   *         UNKNOWN [Initial status]
   *          v  ^
   *        PENDING
   *        v     v
   *  COMMITTED INVALID [Final statuses]
   *
   * This status is not sampled atomically per handler: if this is called
   * multiple times in a transaction handler, later calls may see more up to
   * date values than earlier calls. Once a final state (COMMITTED or INVALID)
   * has been reached, no further changes are possible.
   *
   */
  getStatusForTxId(view: number, seqno: number): TransactionStatus;

  /**
   * Get the view associated with a given seqno, to construct a valid TxID.
   * If the seqno is not known by the node, `null` is returned.
   */
  getViewForSeqno(seqno: number): number | null;
}

export interface CCFHistorical {
  /**
   * Retrieve a range of historical states containing the state written at the given
   * indices.
   *
   * If this is not currently available, this function returns `null`
   * and begins fetching the ledger entry asynchronously. This will generally
   * be true for the first call for a given seqno, and it may take some time
   * to completely fetch and validate. The call should be repeated later with
   * the same arguments to retrieve the requested entries. This state is kept
   * until it is deleted for one of the following reasons:
   *  - A call to {@linkcode dropCachedStates}
   *  - `seconds_until_expiry` seconds elapse without calling this function
   *  - This handle is used to request a different seqno or range
   *
   * The range is inclusive of both start_seqno and end_seqno. If a non-empty
   * array is returned, it will always contain the full requested range; the
   * array will be of length (end_seqno - start_seqno + 1).
   *
   * If the requested range failed to be retrieved then `null` is returned.
   * This may happen if the range is not known to the node (see also
   * {@linkcode global!CCFConsensus.getStatusForTxId | getStatusForTxId}) or not available for
   * other reasons (for example, the node is missing ledger files on disk).
   */
  getStateRange(
    handle: number,
    startSeqno: number,
    endSeqno: number,
    secondsUntilExpiry: number
  ): HistoricalState[] | null;

  /** Drop cached states for the given handle.
   *
   * May be used to free up space once a historical query has been resolved,
   * more aggressively than waiting for the requests to expire.
   *
   * Returns `true` if the handle was found and dropped, `false` otherwise.
   */
  dropCachedStates(handle: number): boolean;
}

export interface CCF {
  /**
   * Convert a string into an ArrayBuffer.
   */
  strToBuf(v: string): ArrayBuffer;

  /**
   * Convert an ArrayBuffer into a string.
   */
  bufToStr(v: ArrayBuffer): string;

  /**
   * Serialize a value to JSON and convert it to an ArrayBuffer.
   *
   * Equivalent to `ccf.strToBuf(JSON.stringify(v))`.
   */
  jsonCompatibleToBuf<T extends JsonCompatible<T>>(v: T): ArrayBuffer;

  /**
   * Parse JSON from an ArrayBuffer.
   *
   * Equivalent to `JSON.parse(ccf.bufToStr(v))`.
   */
  bufToJsonCompatible<T extends JsonCompatible<T>>(v: ArrayBuffer): T;

  /**
   * @deprecated This method has been moved to ccf.crypto namespace
   * @see crypto.generateAesKey
   */
  generateAesKey(size: number): ArrayBuffer;

  /**
   * @deprecated This method has been moved to ccf.crypto namespace
   * @see crypto.generateRsaKeyPair
   */
  generateRsaKeyPair(size: number, exponent?: number): CryptoKeyPair;

  /**
   * @deprecated This method has been moved to ccf.crypto namespace
   * @see crypto.generateEcdsaKeyPair
   */
  generateEcdsaKeyPair(curve: string): CryptoKeyPair;

  /**
   * @deprecated This method has been moved to ccf.crypto namespace
   * @see crypto.wrapKey
   */
  wrapKey(
    key: ArrayBuffer,
    wrappingKey: ArrayBuffer,
    wrapAlgo: WrapAlgoParams
  ): ArrayBuffer;

  /**
   * @deprecated This method has been moved to ccf.crypto namespace
   * @see crypto.digest
   */
  digest(algorithm: DigestAlgorithm, data: ArrayBuffer): ArrayBuffer;

  /**
   * @deprecated
   * @see crypto.isValidX509CertBundle
   */
  isValidX509CertBundle(pem: string): boolean;

  /**
   * @deprecated This method has been moved to ccf.crypto namespace
   * @see crypto.isValidX509CertChain
   */
  isValidX509CertChain(chain: string, trusted: string): boolean;

  crypto: CCFCrypto;

  rpc: CCFRpc;

  consensus: CCFConsensus;

  /**
   * An object that provides access to the maps of the Key-Value Store of CCF.
   * Fields are map names and values are {@linkcode KvMap} objects.
   */
  kv: KvMaps;

  /**
   * State associated with a specific historic transaction.
   * Only defined for endpoints with "mode" set to "historical".
   */
  historicalState?: HistoricalState;

  historical: CCFHistorical;
}

export const openenclave: OpenEnclave = (<any>globalThis).openenclave;

export interface EvidenceClaims {
  claims: { [name: string]: ArrayBuffer };
  customClaims: { [name: string]: ArrayBuffer };
}

export interface OpenEnclave {
  /**
   * Verifies Open Enclave evidence and returns the claims of the evidence.
   *
   * @param format The optional format id of the evidence to be verified as
   *  a UUID of the form "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
   *  If this parameter is `undefined`, the evidence and endorsement
   *  must either contain data with an attestation header holding a valid
   *  format id, or be an Open Enclave report generated by the legacy API function
   *  `oe_get_report()`. Otherwise, this parameter must be a valid format id, and
   *  the evidence and endorsements data must not be wrapped with an attestation header.
   */
  verifyOpenEnclaveEvidence(
    format: string | undefined,
    evidence: ArrayBuffer,
    endorsements?: ArrayBuffer
  ): EvidenceClaims;
}
