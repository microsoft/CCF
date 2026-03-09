// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include <mutex>
#else
#  include <openenclave/3rdparty/libc/pthread.h>
#  include <openenclave/edger8r/enclave.h> // For oe_lfence
#endif

namespace ccf::pal
{
  /**
   * Virtual enclaves and the host code share the same PAL.
   */
  using Mutex = std::mutex;
}