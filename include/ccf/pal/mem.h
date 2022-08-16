// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdlib.h>

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include <cstring>
#  include <limits>
#else
#  include <openenclave/advanced/mallinfo.h>
#  include <openenclave/bits/security.h>
#endif

namespace ccf::pal
{
  /**
   * Malloc information formatted based on the OE type, but avoiding to expose
   * the actual OE type in non-OE code.
   */
  struct MallocInfo
  {
    size_t max_total_heap_size = 0;
    size_t current_allocated_heap_size = 0;
    size_t peak_allocated_heap_size = 0;
  };

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

  static inline void* safe_memcpy(void* dest, const void* src, size_t count)
  {
    return ::memcpy(dest, src, count);
  }

  static inline bool get_mallinfo(MallocInfo& info)
  {
    info.max_total_heap_size = std::numeric_limits<size_t>::max();
    info.current_allocated_heap_size = 0;
    info.peak_allocated_heap_size = 0;
    return true;
  }

#else

  static inline void* safe_memcpy(void* dest, const void* src, size_t count)
  {
    return oe_memcpy_with_barrier(dest, src, count);
  }

  static bool get_mallinfo(MallocInfo& info)
  {
    oe_mallinfo_t oe_info;
    auto rc = oe_allocator_mallinfo(&oe_info);
    if (rc != OE_OK)
    {
      return false;
    }
    info.max_total_heap_size = oe_info.max_total_heap_size;
    info.current_allocated_heap_size = oe_info.current_allocated_heap_size;
    info.peak_allocated_heap_size = oe_info.peak_allocated_heap_size;
    return true;
  }

#endif
}