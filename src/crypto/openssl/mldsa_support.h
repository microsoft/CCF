// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/opensslv.h>

namespace ccf::crypto
{
  /// True when this build's OpenSSL provides ML-DSA (3.5 or newer).
  constexpr bool mldsa_supported()
  {
    return OPENSSL_VERSION_PREREQ(3, 5);
  }
}
