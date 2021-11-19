// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "mbedtls/base64.h"

#include "ds/logger.h"
#include "openssl/base64.h"

namespace crypto
{
#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
  using Base64Impl = Base64_mbedtls;
#else
  using Base64Impl = Base64_openssl;
#endif

  std::vector<uint8_t> raw_from_b64(const std::string_view& b64_string)
  {
    return Base64Impl::raw_from_b64(b64_string);
  }

  std::vector<uint8_t> raw_from_b64url(const std::string_view& b64url_string)
  {
    std::string b64_string = std::string(b64url_string);
    for (size_t i = 0; i < b64_string.size(); i++)
    {
      switch (b64_string[i])
      {
        case '-':
          b64_string[i] = '+';
          break;
        case '_':
          b64_string[i] = '/';
          break;
      }
    }
    auto padding =
      b64_string.size() % 4 == 2 ? 2 : b64_string.size() % 4 == 3 ? 1 : 0;
    b64_string += std::string(padding, '=');
    return raw_from_b64(b64_string);
  }

  std::string b64_from_raw(const uint8_t* data, size_t size)
  {
    return Base64Impl::b64_from_raw(data, size);
  }

  std::string b64_from_raw(const std::vector<uint8_t>& data)
  {
    return b64_from_raw(data.data(), data.size());
  }
}
