// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/context.h"

namespace ccf::js
{
  enum class KVAccessPermissions
  {
    ILLEGAL = 0,
    READ_ONLY = 1 << 0,
    WRITE_ONLY = 1 << 1,
    READ_WRITE = READ_ONLY | WRITE_ONLY
  };
}
