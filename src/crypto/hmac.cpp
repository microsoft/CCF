// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/crypto/hmac.h"

#include "crypto/openssl/hash.h"

#include <limits>
#include <openssl/hmac.h>

namespace ccf::crypto
{
  namespace OpenSSL
  {
    HashBytes hmac(
      MDType type,
      const std::span<const uint8_t>& key,
      const std::span<const uint8_t>& data)
    {
      const auto* o_md_type = OpenSSL::get_md_type(type);
      HashBytes r(EVP_MD_size(o_md_type));
      unsigned int len = 0;
      if (key.size() > std::numeric_limits<int>::max())
      {
        throw std::logic_error("Key size is too large");
      }
      int key_size = static_cast<int>(key.size());
      auto* rc = HMAC(
        o_md_type,
        key.data(),
        key_size,
        data.data(),
        data.size(),
        r.data(),
        &len);
      if (rc == nullptr)
      {
        throw std::logic_error("HMAC Failed");
      }
      return r;
    }
  }

  HashBytes hmac(
    MDType type,
    const std::span<const uint8_t>& key,
    const std::span<const uint8_t>& data)
  {
    return OpenSSL::hmac(type, key, data);
  }
}