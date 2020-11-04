// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "serialise_entry_blit.h"
#include "serialise_entry_json.h"
#include "serialise_entry_msgpack.h"
#include "tx_view.h"

namespace kv
{
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

    using ReadOnlyTxView = kv::ReadOnlyTxView<K, V, KSerialiser, VSerialiser>;
    using TxView = kv::TxView<K, V, KSerialiser, VSerialiser>;

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

  template <typename K, typename V>
  using MsgPackSerialisedMap =
    MapSerialisedWith<K, V, kv::serialisers::MsgPackSerialiser>;

  /** Short name for default-serialised maps, using JSON serialisers. Support
   * for custom types can be added through the DEFINE_JSON_TYPE macros, or by
   * manually implementing nlohmann's to_json and from_json for the custom type.
   */
  template <typename K, typename V>
  using Map = JsonSerialisedMap<K, V>;
}