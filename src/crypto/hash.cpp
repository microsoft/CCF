// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "hash.h"

#include "mbedtls/hash.h"
#include "openssl/hash.h"

#include <openssl/sha.h>

namespace crypto
{
  void default_sha256(const CBuffer& data, uint8_t* h)
  {
    return openssl_sha256(data, h);
  }

  std::vector<uint8_t> SHA256(const std::vector<uint8_t>& data)
  {
    size_t hash_size = EVP_MD_size(OpenSSL::get_md_type(MDType::SHA256));
    std::vector<uint8_t> r(hash_size);
    openssl_sha256(data, r.data());
    return r;
  }
}