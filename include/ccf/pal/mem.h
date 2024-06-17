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

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

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

  static bool require_alignment_for_untrusted_reads()
  {
#  ifdef FORCE_ENABLE_XAPIC_MITIGATION
    return true;
#  else
    return false;
#  endif
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

  static bool is_vulnerable_to_stale_xapic_read()
  {
    CpuidInfo info;

    cpuid(&info, 1, 0);

    // Ignores stepping, looks only at model and family: potentially
    // includes safe instances which differ only by stepping from a vulnerable
    // instance.
    constexpr uint64_t proc_id_mask = 0x000F'0FF0;
    const uint64_t proc_id = info.eax & proc_id_mask;

    // https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/processors-affected-consolidated-product-cpu-model.html
    // 2022 tab, column "Stale Data Read from Legacy xAPIC, CVE-2022-21233,
    // INTEL-SA-00657"
    const std::set<uint64_t> vulnerable_proc_ids{
      0x506C0, // Apollo Lake
      0x506F0, // Denverton (Goldmont)
      0x606A0, // Ice Lake Xeon-SP
      0x606C0, // Ice Lake D
      0x706A0, // Gemini Lake
      0x706E0, // Ice Lake U, Y
      0x80660, // Snow Ridge BTS (Tremont)
      0x806A0, // Lakefield B-step (Tremont)
      0x806C0, // Tiger Lake U
      0x806D0, // Tiger Lake H
      0x90660, // Elkhart Lake (Tremont)
      0x90670, // Alder Lake S (Golden Cove, Gracemont)
      0x906A0, // Alder Lake H (Golden Cove, Gracemont)
      0x906C0, // Jasper Lake (Tremont)
      0xA0670 // Rocket Lake
    };

    const auto it = vulnerable_proc_ids.find(proc_id);
    return it != vulnerable_proc_ids.end();
  }

  static bool require_alignment_for_untrusted_reads()
  {
#  ifdef FORCE_ENABLE_XAPIC_MITIGATION
    return true;
#  else
    static std::optional<bool> required = std::nullopt;
    if (!required.has_value())
    {
      required = is_intel_cpu() && is_vulnerable_to_stale_xapic_read();
    }
    return required.value();
#  endif
  }

#endif
}