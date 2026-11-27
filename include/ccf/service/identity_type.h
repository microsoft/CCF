// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <cstdint>

namespace ccf
{
  /// Cryptographic family of an identity.
  // Preserve the existing 64-bit C++ representation.
  // NOLINTNEXTLINE(performance-enum-size)
  enum class IdentityType : uint64_t
  {
    /// Classical cryptographic identity.
    CLASSICAL = 0,
    /// Post-quantum cryptographic identity.
    PQ = 1,
  };

  DECLARE_JSON_ENUM(
    IdentityType,
    {{IdentityType::CLASSICAL, "CLASSICAL"}, {IdentityType::PQ, "PQ"}});
}
