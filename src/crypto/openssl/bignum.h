// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"

#include <climits>
#include <cstdint>
#include <openssl/bn.h>
#include <span>
#include <stdexcept>

namespace ccf::crypto::OpenSSL
{
  // BN_bin2bn and BN_lebin2bn take an int length, so the size of the input
  // must be checked before it is narrowed.
  inline Unique_BIGNUM bn_from_bytes(
    std::span<const uint8_t> bytes, bool big_endian = true)
  {
    if (bytes.size() > INT_MAX)
    {
      throw std::invalid_argument(fmt::format(
        "Big number size {} exceeds the maximum of {} bytes",
        bytes.size(),
        INT_MAX));
    }
    const auto len = static_cast<int>(bytes.size());

    Unique_BIGNUM bn;
    CHECKNULL(
      big_endian ? BN_bin2bn(bytes.data(), len, bn) :
                   BN_lebin2bn(bytes.data(), len, bn));
    return bn;
  }
}
