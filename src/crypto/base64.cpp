// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "openssl/base64.h"

#include "ccf/ds/logger.h"

namespace ccf::crypto
{
  using Base64Impl = Base64_openssl;

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
    auto padding = b64_string.size() % 4 == 2 ? 2 :
      b64_string.size() % 4 == 3              ? 1 :
                                                0;
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

  std::string b64url_from_raw(
    const uint8_t* data, size_t size, bool with_padding)
  {
    auto r = Base64Impl::b64_from_raw(data, size);

    for (size_t i = 0; i < r.size(); i++)
    {
      switch (r[i])
      {
        case '+':
          r[i] = '-';
          break;
        case '/':
          r[i] = '_';
          break;
      }
    }

    if (!with_padding)
    {
      while (r.ends_with('='))
      {
        r.pop_back();
      }
    }

    return r;
  }

  std::string b64url_from_raw(
    const std::vector<uint8_t>& data, bool with_padding)
  {
    return b64url_from_raw(data.data(), data.size(), with_padding);
  }
}
