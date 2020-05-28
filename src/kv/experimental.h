// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/hash.h"
#include "kv_types.h"
#include "map.h"
#include "tx_view.h"

#include <vector>

namespace kv
{
  namespace experimental
  {
    using SerialisedRep = std::vector<uint8_t>;

    using RepHasher = std::hash<SerialisedRep>;

    using UntypedMap = kv::Map<SerialisedRep, SerialisedRep, RepHasher>;

    using UntypedOperationsView =
      kv::TxView<SerialisedRep, SerialisedRep, RepHasher>;

    using UntypedCommitter =
      kv::TxViewCommitter<SerialisedRep, SerialisedRep, RepHasher>;

    using UntypedState = kv::State<SerialisedRep, SerialisedRep, RepHasher>;

    template <typename T>
    struct MsgPackSerialiser
    {
      static SerialisedRep to_serialised(const T& t)
      {
        msgpack::sbuffer sb;
        msgpack::pack(sb, t);
        auto sb_data = reinterpret_cast<const uint8_t*>(sb.data());
        return SerialisedRep(sb_data, sb_data + sb.size());
      }

      static T from_serialised(const SerialisedRep& rep)
      {
        msgpack::object_handle oh = msgpack::unpack(
          reinterpret_cast<const char*>(rep.data()), rep.size());
        auto object = oh.get();
        return object.as<T>();
      }
    };

    template <typename T>
    struct JsonSerialiser
    {
      static SerialisedRep to_serialised(const T& t)
      {
        const nlohmann::json j = t;
        const auto dumped = j.dump();
        return SerialisedRep(dumped.begin(), dumped.end());
      }

      static T from_serialised(const SerialisedRep& rep)
      {
        const auto j = nlohmann::json::parse(rep);
        return j.get<T>();
      }
    };

    template <
      typename K,
      typename V,
      typename KSerialiser = MsgPackSerialiser<K>,
      typename VSerialiser = MsgPackSerialiser<V>>
    class TxView : public UntypedCommitter
    {
    protected:
      // This _has_ a (non-visible, untyped) view, whereas the standard impl
      // _is_ a typed view
      UntypedOperationsView untyped_view;

    public:
      using KeyType = K;
      using ValueType = V;

      TxView(
        UntypedMap& m,
        size_t rollbacks,
        UntypedState& current_state,
        UntypedState& committed_state,
        Version v) :
        UntypedCommitter(m, rollbacks, current_state, committed_state, v),
        untyped_view(UntypedCommitter::change_set)
      {}

      std::optional<V> get(const K& key)
      {
        const auto k_rep = KSerialiser::to_serialised(key);
        const auto opt_v_rep = untyped_view.get(k_rep);

        if (opt_v_rep.has_value())
        {
          return VSerialiser::from_serialised(*opt_v_rep);
        }

        return std::nullopt;
      }

      std::optional<V> get_globally_committed(const K& key)
      {
        const auto k_rep = KSerialiser::to_serialised(key);
        const auto opt_v_rep = untyped_view.get_globally_committed(k_rep);

        if (opt_v_rep.has_value())
        {
          return VSerialiser::from_serialised(*opt_v_rep);
        }

        return std::nullopt;
      }

      bool put(const K& key, const V& value)
      {
        const auto k_rep = KSerialiser::to_serialised(key);
        const auto v_rep = VSerialiser::to_serialised(value);

        return untyped_view.put(k_rep, v_rep);
      }

      bool remove(const K& key)
      {
        const auto k_rep = KSerialiser::to_serialised(key);

        return untyped_view.remove(k_rep);
      }

      template <class F>
      bool foreach(F&& f)
      {
        auto g = [&](const SerialisedRep& k_rep, const SerialisedRep& v_rep) {
          return f(
            KSerialiser::from_serialised(k_rep),
            VSerialiser::from_serialised(v_rep));
        };
        return untyped_view.foreach(g);
      }
    };

    template <
      typename K,
      typename V,
      typename KSerialiser = MsgPackSerialiser<K>,
      typename VSerialiser = MsgPackSerialiser<V>>
    class Map : public AbstractMap
    {
    protected:
      using This = Map<K, V, KSerialiser, VSerialiser>;

      UntypedMap untyped_map;

    public:
      // Expose correct public aliases of types
      using VersionV = VersionV<V>;

      using Write = Write<K, V>;

      using CommitHook = CommitHook<Write>;

      using TxView = kv::experimental::TxView<K, V, KSerialiser, VSerialiser>;

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

      static UntypedMap::CommitHook wrap_commit_hook(const CommitHook& hook)
      {
        return [hook](Version v, const UntypedMap::Write& w) {
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
}