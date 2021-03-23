// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

import { ccf } from "./global";

export const generateAesKey = ccf.generateAesKey;
export const generateRsaKeyPair = ccf.generateRsaKeyPair;
export const wrapKey = ccf.wrapKey;

export {
  WrapAlgoParams,
  AesKwpParams,
  RsaOaepParams,
  RsaOaepAesKwpParams,
  CryptoKeyPair,
} from "./global";
