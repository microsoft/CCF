// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "tx_view.h"

namespace kv
{
  template <
    typename K,
    typename V,
    typename KSerialiser = MsgPackSerialiser<K>,
    typename VSerialiser = MsgPackSerialiser<V>>
  class Map : public AbstractMap
  {
  protected:
    using This = Map<K, V, KSerialiser, VSerialiser>;

    kv::untyped::Map untyped_map;

  public:
    // Expose correct public aliases of types
    using VersionV = VersionV<V>;

    // TODO: Don't use this Write, use map rather than unordered_map, so K
    // doesn't need std::hash?
    using Write = Write<K, V, std::hash<K>>;

    using CommitHook = CommitHook<Write>;

    using TxView = kv::TxView<K, V, KSerialiser, VSerialiser>;

    template <typename... Ts>
    Map(Ts&&... ts) : untyped_map(std::forward<Ts>(ts)...)
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
      return untyped_map.deserialise(d, version);
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
      return new Map(
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
        Write typed_w;
        for (const auto& [uk, opt_uv] : w)
        {
          if (!opt_uv.has_value())
          {
            // Deletions are indicated by nullopt. We cannot deserialise them,
            // they are deletions here as well
            typed_w[KSerialiser::from_serialised(uk)] = std::nullopt;
          }
          else
          {
            typed_w[KSerialiser::from_serialised(uk)] =
              VSerialiser::from_serialised(opt_uv.value());
          }
        }

        hook(v, typed_w);
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
}