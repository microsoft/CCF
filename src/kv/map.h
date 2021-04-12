// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "map_handle.h"
#include "serialise_entry_blit.h"
#include "serialise_entry_json.h"

namespace kv
{
  /** Defines the schema of a table within the @c kv::Store, exposing associated
   * types.
   *
   * K defines the type of the Key which indexes each entry, while V is the type
   * of the Value associated with a given Key. KSerialiser and VSerialiser
   * determine how each K and V are serialised and deserialised, so they may be
   * written to the ledger and replicated by the consensus algorithm. Note that
   * equality is always evaluated on the serialised form; if unequal Ks produce
   * the same serialisation, they will coincide within this table. Serialiser
   * which leverages existing JSON serialisation is provided by CCF.
   */
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class TypedMap : public NamedMap
  {
  protected:
    using This = TypedMap<K, V, KSerialiser, VSerialiser>;

  public:
    // Expose correct public aliases of types
    using VersionV = VersionV<V>;

    using Write = std::map<K, std::optional<V>>;

    using CommitHook = CommitHook<Write>;
    using MapHook = MapHook<Write>;

    using ReadOnlyHandle =
      kv::ReadableMapHandle<K, V, KSerialiser, VSerialiser>;
    using WriteOnlyHandle =
      kv::WriteableMapHandle<K, V, KSerialiser, VSerialiser>;
    using Handle = kv::MapHandle<K, V, KSerialiser, VSerialiser>;

    using KeySerialiser = KSerialiser;
    using ValueSerialiser = VSerialiser;

    using NamedMap::NamedMap;

    static kv::untyped::Map::CommitHook wrap_commit_hook(const CommitHook& hook)
    {
      return [hook](Version v, const kv::untyped::Write& w) {
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
            typed_writes[KSerialiser::from_serialised(uk)] =
              VSerialiser::from_serialised(opt_uv.value());
          }
        }

        hook(v, typed_writes);
      };
    }

    static kv::untyped::Map::MapHook wrap_map_hook(const MapHook& hook)
    {
      return [hook](Version v, const kv::untyped::Write& w) {
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
            typed_writes[KSerialiser::from_serialised(uk)] =
              VSerialiser::from_serialised(opt_uv.value());
          }
        }

        return hook(v, typed_writes);
      };
    }
  };

  template <
    typename K,
    typename V,
    template <typename>
    typename KSerialiser,
    template <typename> typename VSerialiser = KSerialiser>
  using MapSerialisedWith = TypedMap<K, V, KSerialiser<K>, VSerialiser<V>>;

  template <typename K, typename V>
  using JsonSerialisedMap =
    MapSerialisedWith<K, V, kv::serialisers::JsonSerialiser>;

  template <typename K, typename V>
  using RawCopySerialisedMap = TypedMap<
    K,
    V,
    kv::serialisers::BlitSerialiser<K>,
    kv::serialisers::BlitSerialiser<V>>;
}