// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <cstdlib>

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include <cstring>
#  include <mutex>
#else
#  include "ccf/ds/ccf_exception.h"
#  include "ccf/ds/logger.h"

#  include <openenclave/advanced/mallinfo.h>
#  include <openenclave/attestation/attester.h>
#  include <openenclave/bits/defs.h>
#  include <openenclave/bits/security.h>
#  include <openenclave/edger8r/enclave.h> // For oe_lfence
#  include <openenclave/enclave.h>
#  include <openenclave/log.h>
#  include <openenclave/tracee.h>
#  include <pthread.h>
#endif

/**
 * This file implements a platform abstraction layer to enable platforms, such
 * as OpenEnclave to offer custom implementations for certain functionalities.
 * By centralizing the platform-specific code to one file, we can avoid exposing
 * platform-specific types to the rest of the code and have a good overview of
 * all the functionality that is custom to a given platform. The platform
 * abstraction layer can also be used in code shared between the host and the
 * enclave as there is a host implementation for it as well.
 */
namespace ccf
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
  /**
   * Virtual enclaves and the host code share the same PAL.
   * This PAL takes no dependence on OpenEnclave, but also does not apply
   * security hardening.
   */
  class HostPal
  {
  public:
    using Mutex = std::mutex;

    static inline void* safe_memcpy(void* dest, const void* src, size_t count)
    {
      return ::memcpy(dest, src, count);
    }

    static inline void speculation_barrier() {}

    static inline void redirect_platform_logging() {}

    static inline void initialize_enclave() {}

    static inline void shutdown_enclave() {}

    static inline bool is_outside_enclave(const void* ptr, std::size_t size)
    {
      return true;
    }

    static inline bool get_mallinfo(MallocInfo& info)
    {
      info.max_total_heap_size = std::numeric_limits<size_t>::max();
      info.current_allocated_heap_size = 0;
      info.peak_allocated_heap_size = 0;
      return true;
    }
  };

  using Pal = HostPal;

#else
  class OEPal
  {
    /**
     * Temporary workaround until the fix for
     * https://github.com/openenclave/openenclave/issues/4555 is available in a
     * release.
     */
    class MutexImpl
    {
    private:
      pthread_spinlock_t sl;

    public:
      MutexImpl()
      {
        pthread_spin_init(&sl, PTHREAD_PROCESS_PRIVATE);
      }

      ~MutexImpl()
      {
        pthread_spin_destroy(&sl);
      }

      void lock()
      {
        pthread_spin_lock(&sl);
      }

      bool try_lock()
      {
        return pthread_spin_trylock(&sl) == 0;
      }

      void unlock()
      {
        pthread_spin_unlock(&sl);
      }
    };

  public:
    using Mutex = MutexImpl;
    static inline void* safe_memcpy(void* dest, const void* src, size_t count)
    {
      return oe_memcpy_with_barrier(dest, src, count);
    }

    static inline void speculation_barrier()
    {
      oe_lfence();
    }

    static inline void redirect_platform_logging()
    {
      oe_enclave_log_set_callback(nullptr, &open_enclave_logging_callback);
    }

    static inline void initialize_enclave()
    {
      auto rc = oe_attester_initialize();
      if (rc != OE_OK)
      {
        throw ccf::ccf_oe_attester_init_error(fmt::format(
          "Failed to initialise evidence attester: {}", oe_result_str(rc)));
      }
    }

    static inline void shutdown_enclave()
    {
      oe_attester_shutdown();
    }

    static bool is_outside_enclave(const void* ptr, size_t size)
    {
      return oe_is_outside_enclave(ptr, size);
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

  private:
    static void open_enclave_logging_callback(
      void* context,
      oe_log_level_t level,
      uint64_t thread_id,
      const char* message)
    {
      switch (level)
      {
        case OE_LOG_LEVEL_FATAL:
          CCF_LOG_FMT(FATAL, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_ERROR:
          CCF_LOG_FMT(FAIL, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_WARNING:
          CCF_LOG_FMT(FAIL, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_INFO:
          CCF_LOG_FMT(INFO, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_VERBOSE:
          CCF_LOG_FMT(DEBUG, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_MAX:
        case OE_LOG_LEVEL_NONE:
          CCF_LOG_FMT(TRACE, "")("OE: {}", message);
          break;
      }
    }
  };

  using Pal = OEPal;

#endif
}