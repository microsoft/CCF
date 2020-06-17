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
  class TypedMap : public AbstractMap
  {
  protected:
    using This = TypedMap<K, V, KSerialiser, VSerialiser>;

    kv::untyped::Map untyped_map;

  public:
    // Expose correct public aliases of types
    using VersionV = VersionV<V>;

    using Write = std::map<K, std::optional<V>>;

    using CommitHook = CommitHook<Write>;

    using ReadOnlyTxView = kv::ReadOnlyTxView<K, V, KSerialiser, VSerialiser>;
    using TxView = kv::TxView<K, V, KSerialiser, VSerialiser>;

    template <typename... Ts>
    TypedMap(Ts&&... ts) : untyped_map(std::forward<Ts>(ts)...)
    {}

    bool operator==(const AbstractMap& that) const override
    {
      auto p = dynamic_cast<const This*>(&that);
      if (p == nullptr)
      {
        return false;
      }

      return untyped_map == p->untyped_map;
    }

    bool operator!=(const AbstractMap& that) const override
    {
      return !(*this == that);
    }

    AbstractStore* get_store() override
    {
      return untyped_map.get_store();
    }

    void serialise(
      const AbstractTxView* view,
      KvStoreSerialiser& s,
      bool include_reads) override
    {
      untyped_map.serialise(view, s, include_reads);
    }

    AbstractTxView* deserialise(
      KvStoreDeserialiser& d, Version version) override
    {
      return untyped_map.deserialise_internal<TxView>(d, version);
    }

    const std::string& get_name() const override
    {
      return untyped_map.get_name();
    }

    void compact(Version v) override
    {
      return untyped_map.compact(v);
    }

    void post_compact() override
    {
      return untyped_map.post_compact();
    }

    void rollback(Version v) override
    {
      untyped_map.rollback(v);
    }

    void lock() override
    {
      untyped_map.lock();
    }

    void unlock() override
    {
      untyped_map.unlock();
    }

    SecurityDomain get_security_domain() override
    {
      return untyped_map.get_security_domain();
    }

    bool is_replicated() override
    {
      return untyped_map.is_replicated();
    }

    void clear() override
    {
      untyped_map.clear();
    }

    AbstractMap* clone(AbstractStore* store) override
    {
      return new TypedMap(
        store,
        untyped_map.get_name(),
        untyped_map.get_security_domain(),
        untyped_map.is_replicated());
    }

    void swap(AbstractMap* map) override
    {
      auto p = dynamic_cast<This*>(map);
      if (p == nullptr)
        throw std::logic_error(
          "Attempted to swap maps with incompatible types");

      untyped_map.swap(&p->untyped_map);
    }

    template <typename TView>
    TView* create_view(Version v)
    {
      return untyped_map.create_view<TView>(v);
    }

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

    void set_local_hook(const CommitHook& hook)
    {
      untyped_map.set_local_hook(wrap_commit_hook(hook));
    }

    void unset_local_hook()
    {
      untyped_map.unset_local_hook();
    }

    void set_global_hook(const CommitHook& hook)
    {
      untyped_map.set_global_hook(wrap_commit_hook(hook));
    }

    void unset_global_hook()
    {
      untyped_map.unset_global_hook();
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

  // The default kv::Map will use msgpack serialisers. Custom types are
  // supported through the MSGPACK_DEFINE macro
  template <typename K, typename V>
  using Map = MsgPackSerialisedMap<K, V>;
}