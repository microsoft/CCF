// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_deprecated.h"

#include <cstring>
#include <stdlib.h>

namespace ccf::pal
{
  // Historically wrapped oe_memcpy_with_barrier, but since Open Enclave
  // removal it is exactly ::memcpy. Kept for source compatibility only.
  CCF_DEPRECATED("Use std::memcpy instead")
  static inline void* safe_memcpy(void* dest, const void* src, size_t count)
  {
    return ::memcpy(dest, src, count);
  }
}
