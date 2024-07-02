// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/get_name.h"
#include "ccf/kv/hooks.h"
#include "ccf/kv/serialisers/blit_serialiser.h"
#include "ccf/kv/serialisers/json_serialiser.h"
#include "ccf/kv/set_handle.h"
#include "ccf/kv/untyped.h"

namespace ccf::kv
{
  /** Defines the schema of a set type accessed by a @c ccf::Tx. This set is an
   * unordered container of unique keys. Each key is either present or missing
   * within the set, and key presence can be efficiently tested.
   *
   * K defines the type of each entry in this set. KSerialiser determines how
   * each K is serialised and deserialised, so they may be written to the ledger
   * and replicated by the consensus algorithm. Note that equality is always
   * evaluated on the serialised form; if unequal Ks produce the same
   * serialisation, they will coincide within this set.
   *
   * This is implemented as a @c ccf::kv::Map from K to Unit, and the
   * serialisation of the unit values is overridable with the Unit template
   * parameter.
   */
  template <
    typename K,
    typename KSerialiser,
    typename Unit = ccf::kv::serialisers::ZeroBlitUnitCreator>
  class TypedSet : public GetName
  {
  public:
    using ReadOnlyHandle = ccf::kv::ReadableSetHandle<K, KSerialiser>;
    using WriteOnlyHandle = ccf::kv::WriteableSetHandle<K, KSerialiser, Unit>;
    using Handle = ccf::kv::SetHandle<K, KSerialiser, Unit>;

    // Note: The type V of the value `std::optional<V>` does not matter here.
    // The optional type is required to differentiate additions from deletions,
    // and to provide a consistent interface with the more generic `TypedMap`.
    using Write =
      std::map<K, std::optional<ccf::kv::serialisers::SerialisedEntry>>;
    using MapHook = MapHook<Write>;
    using CommitHook = CommitHook<Write>;

    using Key = K;
    using KeySerialiser = KSerialiser;

    using GetName::GetName;

  private:
    static Write deserialise_write(const ccf::kv::untyped::Write& w)
    {
      Write typed_writes;
      for (const auto& [uk, opt_uv] : w)
      {
        if (!opt_uv.has_value())
        {
          // Deletions are indicated by nullopt. We cannot deserialise them,
          // they are deletions here as well
          typed_writes[KSerialiser::from_serialised(uk)] = std::nullopt;
        }
        else
        {
          typed_writes[KSerialiser::from_serialised(uk)] = Unit::get();
        }
      }
      return typed_writes;
    }

  public:
    static ccf::kv::untyped::CommitHook wrap_commit_hook(const CommitHook& hook)
    {
      return [hook](Version v, const ccf::kv::untyped::Write& w) {
        hook(v, deserialise_write(w));
      };
    }

    static ccf::kv::untyped::MapHook wrap_map_hook(const MapHook& hook)
    {
      return [hook](Version v, const ccf::kv::untyped::Write& w) {
        return hook(v, deserialise_write(w));
      };
    }
  };

  template <
    typename K,
    template <typename>
    typename KSerialiser,
    typename Unit = ccf::kv::serialisers::ZeroBlitUnitCreator>
  using SetSerialisedWith = TypedSet<K, KSerialiser<K>, Unit>;

  template <typename K>
  using JsonSerialisedSet =
    SetSerialisedWith<K, ccf::kv::serialisers::JsonSerialiser>;

  template <typename K>
  using RawCopySerialisedSet =
    TypedSet<K, ccf::kv::serialisers::BlitSerialiser<K>>;

  /** Short name for default-serialised sets, using JSON serialisers. Support
   * for custom types can be added through the DECLARE_JSON... macros.
   */
  template <typename K>
  using Set = JsonSerialisedSet<K>;
}