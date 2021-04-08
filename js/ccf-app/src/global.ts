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
 * import { ccf } from '@microsoft/ccf-app/global';
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
  set(key: ArrayBuffer, value: ArrayBuffer): KvMap;
  delete(key: ArrayBuffer): boolean;
  forEach(
    callback: (value: ArrayBuffer, key: ArrayBuffer, kvmap: KvMap) => void
  ): void;
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
   * Hex-encoded Merkle tree root hash.
   */
  root: string;

  /**
   * Merkle tree inclusion proof as an array of ``ProofElement`` objects.
   */
  proof: Proof;

  /**
   * Hex-encoded Merkle tree leaf hash.
   */
  leaf: string;

  /**
   * ID of the node that signed the Merkle tree root hash.
   */
  nodeId: string;
}

/**
 * State associated with a specific historic transaction.
 */
export interface HistoricalState {
  /**
   * The ID of the transaction.
   */
  transactionId: string;

  /**
   * The receipt for the historic transaction.
   */
  receipt: Receipt;
}

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
   * RSA private key in PEM encoding.
   */
  privateKey: string;

  /**
   * RSA public key in PEM encoding.
   */
  publicKey: string;
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
   * Returns whether a string is a PEM-encoded bundle of X.509 certificates.
   *
   * A bundle consists of one or more certificates.
   * Certificates in the bundle do not have to be related to each other.
   * Validation is only syntactical, properties like validity dates are not evaluated.
   */
  isValidX509CertBundle(pem: string): boolean;

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
}
