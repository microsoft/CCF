// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "serialise_entry_blit.h"
#include "serialise_entry_json.h"
#include "value_handle.h"

// TODO: Docs
namespace kv
{
  template <typename V, typename VSerialiser>
  class TypedValue : public NamedHandleMixin
  {
  protected:
    using This = TypedValue<V, VSerialiser>;

  public:
    using ReadOnlyHandle = kv::ReadableValueHandle<V, VSerialiser>;
    using WriteOnlyHandle = kv::WriteableValueHandle<V, VSerialiser>;
    using Handle = kv::ValueHandle<V, VSerialiser>;

    using ValueSerialiser = VSerialiser;

    using NamedHandleMixin::NamedHandleMixin;
  };

  template <typename V, template <typename> typename VSerialiser>
  using ValueSerialisedWith = TypedValue<V, VSerialiser<V>>;

  template <typename V>
  using JsonSerialisedValue =
    ValueSerialisedWith<V, kv::serialisers::JsonSerialiser>;

  template <typename V>
  using RawCopySerialisedValue =
    TypedValue<V, kv::serialisers::BlitSerialiser<V>>;

  template <typename V>
  using Value = JsonSerialisedValue<V>;
}