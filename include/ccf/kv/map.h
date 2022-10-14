// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/get_name.h"
#include "ccf/kv/hooks.h"
#include "ccf/kv/map_diff.h"
#include "ccf/kv/map_handle.h"
#include "ccf/kv/serialisers/blit_serialiser.h"
#include "ccf/kv/serialisers/json_serialiser.h"
#include "ccf/kv/untyped.h"

namespace kv
{
  /** Defines the schema of a map accessed by a @c ccf::Tx, exposing associated
   * types. This map is an unordered associative container of key-value pairs.
   * Each key, if defined, is associated with a value, and can be used to
   * efficiently lookup that value.
   *
   * K defines the type of the Key which indexes each entry, while V is the type
   * of the Value associated with a given Key. KSerialiser and VSerialiser
   * determine how each K and V are serialised and deserialised, so they may be
   * written to the ledger and replicated by the consensus algorithm. Note that
   * equality is always evaluated on the serialised form; if unequal Ks produce
   * the same serialisation, they will coincide within this map. Serialiser
   * which leverages existing JSON serialisation is provided by CCF.
   */
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class TypedMap : public GetName
  {
  public:
    // Expose correct public aliases of types
    using ReadOnlyHandle =
      kv::ReadableMapHandle<K, V, KSerialiser, VSerialiser>;
    using WriteOnlyHandle =
      kv::WriteableMapHandle<K, V, KSerialiser, VSerialiser>;
    using Handle = kv::MapHandle<K, V, KSerialiser, VSerialiser>;
    using Diff = kv::MapDiff<K, V, KSerialiser, VSerialiser>;

    using Write = std::map<K, std::optional<V>>;
    using CommitHook = CommitHook<Write>;
    using MapHook = MapHook<Write>;

    using Key = K;
    using Value = V;
    using KeySerialiser = KSerialiser;
    using ValueSerialiser = VSerialiser;

    using GetName::GetName;

  private:
    static Write deserialise_write(const kv::untyped::Write& w)
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
          typed_writes[KSerialiser::from_serialised(uk)] =
            VSerialiser::from_serialised(opt_uv.value());
        }
      }
      return typed_writes;
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

  /** Short name for default-serialised maps, using JSON serialisers. Support
   * for custom types can be added through the DECLARE_JSON... macros.
   */
  template <typename K, typename V>
  using Map = JsonSerialisedMap<K, V>;
}