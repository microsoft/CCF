// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf::kv
{
  // Version indexes modifications to the local kv store.
  using Version = uint64_t;
  static constexpr Version NoVersion = 0u;
}
