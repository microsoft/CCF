// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "map.h"

namespace kv
{
  namespace typed
  {
    using ByteVector = std::vector<uint8_t>;

    template <class H = std::hash<ByteVector>>
    using UntypedMap = kv::Map<ByteVector, ByteVector, H>;

    template <class K, class V, class H = std::hash<ByteVector>>
    class Map : public UntypedMap<H>
    {
      using Base = UntypedMap<H>;
      using TypedBase = kv::Map<K, V>;
      using This = Map<K, V, H>;

    public:
      using Base::Base;

      // TODO: Work out if this can be moved out of the Map's definition
      class TxView : public kv::AbstractTxView
      {
      public:
        TxView(typename TypedBase::State& s, Version v) {}
      };

      bool operator==(const AbstractMap& that) const override
      {
        auto p = dynamic_cast<const This*>(&that);
        if (p == nullptr)
          return false;

        return Base::operator==(that);
      }

      bool operator!=(const AbstractMap& that) const override
      {
        return !(*this == that);
      }

      kv::AbstractTxView* create_view(Version version) override
      {
        return Base::template create_view_internal<TxView>(
          version, [this](typename TypedBase::State& s, Version v) {
            return TxView(s, v);
          });
      }
    };
  }
}