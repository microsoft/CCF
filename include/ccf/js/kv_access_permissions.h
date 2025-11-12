// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/context.h"

namespace ccf::js
{
  enum class KVAccessPermissions : uint8_t
  {
    ILLEGAL = 0,
    READ_ONLY = 1 << 0,
    WRITE_ONLY = 1 << 1,
    READ_WRITE = READ_ONLY | WRITE_ONLY
  };

  inline KVAccessPermissions intersect_access_permissions(
    KVAccessPermissions l, KVAccessPermissions r)
  {
    /* This could use std::to_underlying from C++23 */
    using T = std::underlying_type_t<KVAccessPermissions>;
    const auto intersection = (T)l & (T)r;
    return KVAccessPermissions(intersection);
  }
}
