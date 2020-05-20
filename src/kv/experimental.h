// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/hash.h"
#include "kv_types.h"
#include "map.h"
#include "tx_view.h"

#include <vector>

namespace kv
{
  namespace experimental
  {
    using SerialisedRep = std::vector<uint8_t>;

    template <typename H>
    using UntypedMap = kv::Map<SerialisedRep, SerialisedRep, H>;

    template <typename K, typename V, typename H = std::hash<SerialisedRep>>
    class Map : public UntypedMap<H>
    {
    protected:
      using Base = UntypedMap<H>;

    public:
      using Base::Base;
      
      AbstractTxView* create_view(Version version) override
      {
        // TODO
        return Base::create_view(version);
      }
    };
  }
}