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
    Version read_version;
    V value;

    VersionV() :
      version(std::numeric_limits<decltype(version)>::min()),
      read_version(std::numeric_limits<decltype(read_version)>::min())
    {}

    VersionV(Version ver, Version read_ver, V val) :
      version(ver),
      read_version(read_ver),
      value(std::move(val))
    {}
  };
}