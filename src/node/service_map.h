// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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