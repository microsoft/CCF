// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

/**
 * The `crypto` module provides access to common cryptographic
 * algorithms.
 *
 * Example:
 * ```
 * import * as ccfcrypto from '@microsoft/ccf-app/crypto.js';
 *
 * const key = ccfcrypto.generateAesKey(128);
 * ```
 *
 * @module
 */

import { ccf } from "./global.js";

/**
 * @inheritDoc global!CCF.generateAesKey
 */
export const generateAesKey = ccf.crypto.generateAesKey;

/**
 * @inheritDoc global!CCF.generateRsaKeyPair
 */
export const generateRsaKeyPair = ccf.crypto.generateRsaKeyPair;

/**
 * @inheritDoc global!CCF.generateEcdsaKeyPair
 */
export const generateEcdsaKeyPair = ccf.crypto.generateEcdsaKeyPair;

/**
 * @inheritDoc global!CCF.generateEcdsaKeyPair
 */
export const generateEddsaKeyPair = ccf.crypto.generateEddsaKeyPair;

/**
 * @inheritDoc global!CCF.wrapKey
 */
export const wrapKey = ccf.crypto.wrapKey;

/**
 * @inheritDoc global!CCFCrypto.verifySignature
 */
export const sign = ccf.crypto.sign;

/**
 * @inheritDoc global!CCFCrypto.verifySignature
 */
export const verifySignature = ccf.crypto.verifySignature;

/**
 * @inheritDoc global!CCFCrypto.digest
 */
export const digest = ccf.crypto.digest;

/**
 * @inheritDoc global!CCFCrypto.isValidX509CertBundle
 */
export const isValidX509CertBundle = ccf.crypto.isValidX509CertBundle;

/**
 * @inheritDoc global!CCFCrypto.isValidX509CertChain
 */
export const isValidX509CertChain = ccf.crypto.isValidX509CertChain;

/**
 * @inheritDoc global!CCFCrypto.pubPemToJwk
 */
export const pubPemToJwk = ccf.crypto.pubPemToJwk;

/**
 * @inheritDoc global!CCFCrypto.pemToJwk
 */
export const pemToJwk = ccf.crypto.pemToJwk;

/**
 * @inheritDoc global!CCFCrypto.pubRsaPemToJwk
 */
export const pubRsaPemToJwk = ccf.crypto.pubRsaPemToJwk;

/**
 * @inheritDoc global!CCFCrypto.rsaPemToJwk
 */
export const rsaPemToJwk = ccf.crypto.rsaPemToJwk;

export {
  WrapAlgoParams,
  AesKwpParams,
  RsaOaepParams,
  RsaOaepAesKwpParams,
  CryptoKeyPair,
  DigestAlgorithm,
  SigningAlgorithm,
} from "./global";
