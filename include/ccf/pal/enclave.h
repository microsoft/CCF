// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdlib.h>

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#else
#  include <openenclave/attestation/attester.h>
#  include <openenclave/enclave.h>
#  include <openenclave/log.h>
#  include <openenclave/tracee.h>
#endif

namespace ccf::pal
{
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

  static inline void redirect_platform_logging() {}

  static inline void initialize_enclave() {}

  static inline void shutdown_enclave() {}

  static inline bool is_outside_enclave(const void* ptr, std::size_t size)
  {
    return true;
  }

#else

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

#endif
}