// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <cstring>
#include <set>

namespace ccf::pal
{
  struct CpuidInfo
  {
    uint64_t eax;
    uint64_t ebx;
    uint64_t ecx;
    uint64_t edx;
  };

  static void cpuid(CpuidInfo* info, uint64_t leaf, uint64_t subleaf)
  {
    asm volatile(
      "cpuid"
      : "=a"(info->eax), "=b"(info->ebx), "=c"(info->ecx), "=d"(info->edx)
      : "a"(leaf), "c"(subleaf));
  }

  static bool is_intel_cpu()
  {
    thread_local int intel_cpu = -1;

    if (intel_cpu == -1)
    {
      CpuidInfo info;
      cpuid(&info, 0, 0);

      if (
        memcmp((char*)&info.ebx, "Genu", 4) ||
        memcmp((char*)&info.edx, "ineI", 4) ||
        memcmp((char*)&info.ecx, "ntel", 4))
      {
        intel_cpu = 1;
      }
      else
      {
        intel_cpu = 0;
      }
    }

    return intel_cpu == 1;
  }
}