// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include <cstdint>

namespace ccf::crypto
{
  enum class MLDSAParameterSet : uint8_t
  {
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87
  };
}
#endif // OPENSSL_VERSION_PREREQ
