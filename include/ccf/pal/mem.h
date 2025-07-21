// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdlib.h>

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include <cstring>
#  include <limits>
#  include <sys/resource.h>
#else
#  include "ccf/pal/hardware_info.h"

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

  static inline void* safe_memcpy(void* dest, const void* src, size_t count)
  {
    return ::memcpy(dest, src, count);
  }

  static inline bool get_mallinfo(MallocInfo& info)
  {
    {
      rusage ru;
      auto rc = getrusage(RUSAGE_SELF, &ru);
      if (rc != 0)
      {
        return false;
      }
      const auto heap_size = ru.ru_maxrss * 1024;

      info.current_allocated_heap_size = heap_size;
      info.peak_allocated_heap_size = heap_size;
    }

    {
      rlimit rl;
      auto rc = getrlimit(RLIMIT_AS, &rl);
      if (rc != 0)
      {
        return false;
      }

      info.max_total_heap_size = rl.rlim_cur;
    }

    return true;
  }
}