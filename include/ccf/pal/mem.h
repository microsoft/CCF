// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstring>
#include <stdlib.h>

namespace ccf::pal
{
  static inline void* safe_memcpy(void* dest, const void* src, size_t count)
  {
    return ::memcpy(dest, src, count);
  }
}