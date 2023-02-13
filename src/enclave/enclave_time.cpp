// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/enclave_time.h"

namespace ccf::enclavetime
{
  std::atomic<long long>* host_time_us = nullptr;
  std::atomic<std::chrono::microseconds> last_value(
    std::chrono::microseconds(0));
}