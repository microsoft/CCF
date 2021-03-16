// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/pem.h"
#include "kv/map.h"

namespace ccf
{
  template <typename K, typename V>
  using ServiceMap = kv::MapSerialisedWith<
    K,
    V,
    kv::serialisers::BlitSerialiser,
    kv::serialisers::JsonSerialiser>;
}

// TODO: Move elsewhere
namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<crypto::Pem>
  {
    static SerialisedEntry to_serialised(const crypto::Pem& pem)
    {
      const auto& data = pem.raw();
      return SerialisedEntry(data.begin(), data.end());
    }

    static crypto::Pem from_serialised(const SerialisedEntry& data)
    {
      return crypto::Pem(data.data(), data.size());
    }
  };
}
