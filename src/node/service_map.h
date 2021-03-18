// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/map.h"

namespace ccf
{
  // This type should be used for most service key-value maps so that:
  // - The raw key is trivially and cheaply deserialisable.
  // - The JSON value can conveniently be audited offline.
  // Note: Maps which include large values (e.g. certificate or serialised
  // Merkle tree) can use the `kv::RawCopySerialisedMap` type to maximise
  // performance.
  template <typename K, typename V>
  using ServiceMap = kv::MapSerialisedWith<
    K,
    V,
    kv::serialisers::BlitSerialiser,
    kv::serialisers::JsonSerialiser>;
}