// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "serialise_entry_blit.h"
#include "serialise_entry_json.h"
#include "set_handle.h"

// TODO: Docs
namespace kv
{
  template <typename K, typename KSerialiser, typename Unit= kv::UnitCreator>
  class TypedSet : public NamedHandleMixin
  {
  protected:
    using This = TypedSet<K, KSerialiser>;

  public:
    using ReadOnlyHandle = kv::ReadableSetHandle<K, KSerialiser>;
    using WriteOnlyHandle = kv::WriteableSetHandle<K, KSerialiser, Unit>;
    using Handle = kv::SetHandle<K, KSerialiser, Unit>;

    using KeySerialiser = KSerialiser;

    using NamedHandleMixin::NamedHandleMixin;
  };

  template <
    typename K,
    template <typename>
    typename KSerialiser,
    typename Unit = kv::UnitCreator>
  using SetSerialisedWith = TypedSet<K, KSerialiser<K>, Unit>;

  template <typename K>
  using JsonSerialisedSet =
    SetSerialisedWith<K, kv::serialisers::JsonSerialiser>;

  template <typename K>
  using RawCopySerialisedSet = TypedSet<K, kv::serialisers::BlitSerialiser<K>>;

  template <typename K>
  using Set = JsonSerialisedSet<K>;
}