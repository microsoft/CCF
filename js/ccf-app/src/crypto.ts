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
 * @inheritDoc CCF.generateAesKey
 */
export const generateAesKey = ccf.generateAesKey;

/**
 * @inheritDoc CCF.generateRsaKeyPair
 */
export const generateRsaKeyPair = ccf.generateRsaKeyPair;

/**
 * @inheritDoc CCF.wrapKey
 */
export const wrapKey = ccf.wrapKey;

/**
 * @inheritDoc CCF.digest
 */
export const digest = ccf.digest;

export {
  WrapAlgoParams,
  AesKwpParams,
  RsaOaepParams,
  RsaOaepAesKwpParams,
  CryptoKeyPair,
  DigestAlgorithm,
} from "./global";
