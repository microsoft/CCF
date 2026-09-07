// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/context.h"

#include <utility>

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
    const auto intersection = std::to_underlying(l) & std::to_underlying(r);
    return static_cast<KVAccessPermissions>(intersection);
  }
}
