// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "serialise_entry_blit.h"
#include "serialise_entry_json.h"
#include "set_handle.h"

namespace kv
{
  /** Defines the schema of a set type within the @c kv::Store. This set is an
   * unordered container of unique keys. Each key is either present or missing
   * within the set, and key presence can be efficiently tested.
   *
   * K defines the type of each entry in this set. KSerialiser determines how
   * each K is serialised and deserialised, so they may be written to the ledger
   * and replicated by the consensus algorithm. Note that equality is always
   * evaluated on the serialised form; if unequal Ks produce the same
   * serialisation, they will coincide within this set.
   *
   * This is implemented as a @c kv::Map from K to Unit, and the serialisation
   * of the unit values is overridable with the Unit template parameter.
   */
  template <
    typename K,
    typename KSerialiser,
    typename Unit = kv::serialisers::ZeroBlitUnitCreator>
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
    typename Unit = kv::serialisers::ZeroBlitUnitCreator>
  using SetSerialisedWith = TypedSet<K, KSerialiser<K>, Unit>;

  template <typename K>
  using JsonSerialisedSet =
    SetSerialisedWith<K, kv::serialisers::JsonSerialiser>;

  template <typename K>
  using RawCopySerialisedSet = TypedSet<K, kv::serialisers::BlitSerialiser<K>>;

  /** Short name for default-serialised sets, using JSON serialisers. Support
   * for custom types can be added through the DECLARE_JSON... macros.
   */
  template <typename K>
  using Set = JsonSerialisedSet<K>;
}