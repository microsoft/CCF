// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <mutex>

namespace ccf::pal
{
  /**
   * Virtual enclaves and the host code share the same PAL.
   */
  using Mutex = std::mutex;
}