// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "serialise_entry_blit.h"
#include "serialise_entry_json.h"
#include "value_handle.h"

namespace kv
{
  /** Defines the schema of a value type within the @c kv::Store. This value
   * type is a container for an optional single element of type V. This may be
   * undefined if the value has not been written to the KV, or else it has the
   * value from the current or last-applied transaction.
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
  class TypedValue : public NamedHandleMixin
  {
  protected:
    using This = TypedValue<V, VSerialiser>;

  public:
    using ReadOnlyHandle = kv::ReadableValueHandle<V, VSerialiser, Unit>;
    using WriteOnlyHandle = kv::WriteableValueHandle<V, VSerialiser, Unit>;
    using Handle = kv::ValueHandle<V, VSerialiser, Unit>;

    using ValueSerialiser = VSerialiser;

    using NamedHandleMixin::NamedHandleMixin;
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