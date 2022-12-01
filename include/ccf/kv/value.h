// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/get_name.h"
#include "ccf/kv/hooks.h"
#include "ccf/kv/serialisers/blit_serialiser.h"
#include "ccf/kv/serialisers/json_serialiser.h"
#include "ccf/kv/untyped.h"
#include "ccf/kv/value_handle.h"

namespace kv
{
  /** Defines the schema of a single-valued type accessed by a @c ccf::Tx. This
   * value type is a container for an optional single element of type V. This
   * may be undefined if the value has not been written to the KV, or else it
   * has the value from the current or last-applied transaction.
   *
   * V defines the type of the contained Value. VSerialiser determines how
   * this V is serialised and deserialised, so it may be written to the ledger
   * and replicated by the consensus algorithm.
   *
   * This is implemented as a @c kv::Map from Unit to V, and the serialisation
   * of the unit key is overridable with the Unit template parameter.
   */
  template <
    typename V,
    typename VSerialiser,
    typename Unit = kv::serialisers::ZeroBlitUnitCreator>
  class TypedValue : public GetName
  {
  public:
    using ReadOnlyHandle = kv::ReadableValueHandle<V, VSerialiser, Unit>;
    using WriteOnlyHandle = kv::WriteableValueHandle<V, VSerialiser, Unit>;
    using Handle = kv::ValueHandle<V, VSerialiser, Unit>;

    using Write = std::optional<V>;
    using MapHook = MapHook<Write>;
    using CommitHook = CommitHook<Write>;

    using Value = V;
    using ValueSerialiser = VSerialiser;

    using GetName::GetName;

    static kv::serialisers::SerialisedEntry create_unit()
    {
      return Unit::get();
    }

  private:
    static Write deserialise_write(const kv::untyped::Write& w)
    {
      assert(w.size() == 1); // Value contains only one element
      const auto& value = w.begin()->second;
      if (!value.has_value())
      {
        return std::nullopt;
      }
      return VSerialiser::from_serialised(value.value());
    }

  public:
    static kv::untyped::CommitHook wrap_commit_hook(const CommitHook& hook)
    {
      return [hook](Version v, const kv::untyped::Write& w) {
        hook(v, deserialise_write(w));
      };
    }

    static kv::untyped::MapHook wrap_map_hook(const MapHook& hook)
    {
      return [hook](Version v, const kv::untyped::Write& w) {
        return hook(v, deserialise_write(w));
      };
    }
  };

  template <
    typename V,
    template <typename>
    typename VSerialiser,
    typename Unit = kv::serialisers::ZeroBlitUnitCreator>
  using ValueSerialisedWith = TypedValue<V, VSerialiser<V>, Unit>;

  template <typename V>
  using JsonSerialisedValue =
    ValueSerialisedWith<V, kv::serialisers::JsonSerialiser>;

  template <typename V>
  using RawCopySerialisedValue =
    TypedValue<V, kv::serialisers::BlitSerialiser<V>>;

  /** Short name for default-serialised values, using JSON serialisers. Support
   * for custom types can be added through the DECLARE_JSON... macros.
   */
  template <typename V>
  using Value = JsonSerialisedValue<V>;
}