// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "openssl/base64.h"

#include "ds/internal_logger.h.h"

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
    for (char& c : b64_string)
    {
      switch (c)
      {
        case '-':
          c = '+';
          break;
        case '_':
          c = '/';
          break;
        default:
          continue;
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

    for (char& c : r)
    {
      switch (c)
      {
        case '+':
          c = '-';
          break;
        case '/':
          c = '_';
          break;
        default:
          continue;
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
