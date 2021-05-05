// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/enclave_time.h"

namespace enclave
{
  std::atomic<std::chrono::microseconds>* host_time = nullptr;
  std::chrono::microseconds last_value(0);
}