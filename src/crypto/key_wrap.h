// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rsa_key_pair.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace crypto
{
  // PKCS11 2.1.21 CKM_RSA_AES_KEY_WRAP wrap
  // @param key_size Key size 128, 192 or 256.
  std::vector<uint8_t> ckm_rsa_aes_key_wrap(
    size_t aes_key_size,
    RSAPublicKeyPtr rsa_public,
    const std::vector<uint8_t>& target_key);

  // PKCS11 2.1.21 CKM_RSA_AES_KEY_WRAP unwrap
  std::vector<uint8_t> ckm_rsa_aes_key_unwrap(
    const std::vector<uint8_t>& cipher, RSAKeyPairPtr rsakp);
}
