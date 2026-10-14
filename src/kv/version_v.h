// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf::kv
{
  using Version = uint64_t;

  template <typename V>
  struct VersionV
  {
    Version version;
    V value;

    VersionV() : version(std::numeric_limits<decltype(version)>::min()) {}

    VersionV(Version ver, V val) : version(ver), value(std::move(val)) {}
  };
}