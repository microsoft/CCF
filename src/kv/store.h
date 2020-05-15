// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "map.h"
#include "views.h"

namespace kv
{
  class Store : public AbstractStore
  {
  public:
    template <class K, class V, class H = std::hash<K>>
    using Map = Map<K, V, H>;

  private:
    // All collections of Map must be ordered so that we lock their contained
    // maps in a stable order. The order here is by map name
    using Maps = std::map<std::string, std::unique_ptr<AbstractMap>>;
    Maps maps;

    std::shared_ptr<Consensus> consensus = nullptr;
    std::shared_ptr<TxHistory> history = nullptr;
    std::shared_ptr<AbstractTxEncryptor> encryptor = nullptr;
    Version version = 0;
    Version compacted = 0;

    SpinLock maps_lock;
    SpinLock version_lock;

    std::unordered_map<Version, std::pair<PendingTx, bool>> pending_txs;
    Version last_replicated = 0;
    Version last_committable = 0;
    Version rollback_count = 0;
    kv::ReplicateType replicate_type = kv::ReplicateType::ALL;
    std::unordered_set<std::string> replicated_tables;

    inline std::map<kv::SecurityDomain, std::vector<AbstractMap*>>
    get_maps_grouped_by_domain(
      const std::map<std::string, std::unique_ptr<AbstractMap>>& maps)
    {
      std::map<kv::SecurityDomain, std::vector<AbstractMap*>> grouped_maps;
      for (auto it = maps.begin(); it != maps.end(); ++it)
      {
        grouped_maps[it->second->get_security_domain()].push_back(
          it->second.get());
      }
      return grouped_maps;
    }

    DeserialiseSuccess commit_deserialised(OrderedViews& views, Version& v)
    {
      auto c = apply_views(views, [v]() { return v; });
      if (!c.has_value())
      {
        LOG_FAIL_FMT("Failed to commit deserialised Tx at version {}", v);
        return DeserialiseSuccess::FAILED;
      }
      {
        std::lock_guard<SpinLock> vguard(version_lock);
        version = v;
        last_replicated = version;
      }
      return DeserialiseSuccess::PASS;
    }

  public:
    void clone_schema(Store& target)
    {
      std::lock_guard<SpinLock> mguard(maps_lock);

      if ((maps.size() != 0) || (version != 0))
        throw std::logic_error("Cannot clone schema on a non-empty store");

      for (auto& [name, map] : target.maps)
      {
        maps[name] = std::unique_ptr<AbstractMap>(map->clone(this));
      }
    }

    Store() {}

    Store(
      const ReplicateType& replicate_type_,
      const std::unordered_set<std::string>& replicated_tables_) :
      replicate_type(replicate_type_),
      replicated_tables(replicated_tables_)
    {}

    Store(std::shared_ptr<Consensus> consensus_) : consensus(consensus_) {}

    Store(const Store& that) = delete;

    std::shared_ptr<Consensus> get_consensus() override
    {
      return consensus;
    }

    void set_consensus(std::shared_ptr<Consensus> consensus_)
    {
      consensus = consensus_;
    }

    std::shared_ptr<TxHistory> get_history() override
    {
      return history;
    }

    void set_history(std::shared_ptr<TxHistory> history_)
    {
      history = history_;
    }

    void set_encryptor(std::shared_ptr<AbstractTxEncryptor> encryptor_)
    {
      encryptor = encryptor_;
    }

    std::shared_ptr<AbstractTxEncryptor> get_encryptor() override
    {
      return encryptor;
    }

    template <class K, class V, class H = std::hash<K>>
    Map<K, V, H>* get(std::string name)
    {
      return get<Map<K, V, H>>(name);
    }

    /** Get Map by name
     *
     * @param name Map name
     *
     * @return Map
     */
    template <class M>
    M* get(std::string name)
    {
      std::lock_guard<SpinLock> mguard(maps_lock);

      auto search = maps.find(name);
      if (search != maps.end())
      {
        auto result = dynamic_cast<M*>(search->second.get());

        if (result == nullptr)
          return nullptr;

        return result;
      }

      return nullptr;
    }

    /** Create a Map
     *
     * Note this call will throw a logic_error if a map by that name already
     * exists.
     *
     * @param name Map name
     * @param global_hook Handler to execute on global commit
     *
     * @return Newly created Map
     */
    template <class K, class V, class H = std::hash<K>>
    Map<K, V, H>& create(
      std::string name,
      SecurityDomain security_domain = kv::SecurityDomain::PRIVATE,
      typename Map<K, V, H>::CommitHook local_hook = nullptr,
      typename Map<K, V, H>::CommitHook global_hook = nullptr)
    {
      return create<Map<K, V, H>>(
        name, security_domain, local_hook, global_hook);
    }

    /** Create a Map
     *
     * Note this call will throw a logic_error if a map by that name already
     * exists.
     *
     * @param name Map name
     * @param global_hook Handler to execute on global commit
     *
     * @return Newly created Map
     */
    template <class M>
    M& create(
      std::string name,
      SecurityDomain security_domain = kv::SecurityDomain::PRIVATE,
      typename M::CommitHook local_hook = nullptr,
      typename M::CommitHook global_hook = nullptr)
    {
      std::lock_guard<SpinLock> mguard(maps_lock);

      auto search = maps.find(name);
      if (search != maps.end())
        throw std::logic_error("Map already exists");
      auto replicated = true;
      if (replicate_type == kv::ReplicateType::NONE)
      {
        replicated = false;
      }
      else if (replicate_type == kv::ReplicateType::SOME)
      {
        if (replicated_tables.find(name) == replicated_tables.end())
        {
          replicated = false;
        }
      }

      auto result =
        new M(this, name, security_domain, replicated, local_hook, global_hook);
      maps[name] = std::unique_ptr<AbstractMap>(result);
      return *result;
    }

    void compact(Version v) override
    {
      // This is called when the store will never be rolled back to any
      // state before the specified version.
      // No transactions can be prepared or committed during compaction.
      std::lock_guard<SpinLock> mguard(maps_lock);

      if (v > current_version())
        return;

      for (auto& map : maps)
        map.second->lock();

      for (auto& map : maps)
        map.second->compact(v);

      for (auto& map : maps)
        map.second->unlock();

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        compacted = v;

        auto h = get_history();
        if (h)
          h->compact(v);

        auto e = get_encryptor();
        if (e)
          e->compact(v);
      }

      for (auto& map : maps)
        map.second->post_compact();
    }

    void rollback(Version v) override
    {
      // This is called to roll the store back to the state it was in
      // at the specified version.
      // No transactions can be prepared or committed during rollback.
      std::lock_guard<SpinLock> mguard(maps_lock);

      if (v >= current_version())
        return;

      if (v < commit_version())
        return;

      for (auto& map : maps)
        map.second->lock();

      for (auto& map : maps)
        map.second->rollback(v);

      for (auto& map : maps)
        map.second->unlock();

      std::lock_guard<SpinLock> vguard(version_lock);
      version = v;
      last_replicated = v;
      last_committable = v;
      rollback_count++;
      pending_txs.clear();
      auto h = get_history();
      if (h)
        h->rollback(v);
      auto e = get_encryptor();
      if (e)
        e->rollback(v);
    }

    DeserialiseSuccess deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr,
      ViewContainer* tx = nullptr)
    {
      // If we pass in a transaction we don't want to commit, just deserialise
      // and put the views into that transaction.
      // Tread carefully here: at the moment passing in a transaction assumes we
      // are using pbft as the consensus and that we are deserialising for
      // playback purposes
      auto commit = (tx == nullptr);

      // This will return FAILED if the serialised transaction is being
      // applied out of order.
      // Processing transactions locally and also deserialising to the
      // same store will result in a store version mismatch and
      // deserialisation will then fail.
      auto e = get_encryptor();

      // create the first deserialiser
      auto d = std::make_unique<D>(
        e,
        public_only ? kv::SecurityDomain::PUBLIC :
                      std::optional<kv::SecurityDomain>());

      if (!d->init(data.data(), data.size()))
      {
        LOG_FAIL_FMT("Initialisation of deserialise object failed");
        return DeserialiseSuccess::FAILED;
      }

      Version v = d->template deserialise_version<Version>();
      // Throw away any local commits that have not propagated via the
      // consensus.
      rollback(v - 1);

      // Make sure this is the next transaction.
      auto cv = current_version();
      if (cv != (v - 1))
      {
        LOG_FAIL_FMT(
          "Tried to deserialise {} but current_version is {}", v, cv);
        return DeserialiseSuccess::FAILED;
      }

      // Deserialised transactions express read dependencies as versions,
      // rather than with the actual value read. As a result, they don't
      // need snapshot isolation on the map state, and so do not need to
      // lock all the maps before creating the transaction.
      std::lock_guard<SpinLock> mguard(maps_lock);
      OrderedViews views;

      for (auto r = d->start_map(); r.has_value(); r = d->start_map())
      {
        const auto map_name = r.value();

        auto search = maps.find(map_name);
        if (search == maps.end())
        {
          LOG_FAIL_FMT("No such map {} at version {}", map_name, v);
          return DeserialiseSuccess::FAILED;
        }

        auto view_search = views.find(map_name);
        if (view_search != views.end())
        {
          LOG_FAIL_FMT("Multiple writes on {} at version {}", map_name, v);
          return DeserialiseSuccess::FAILED;
        }

        auto view = search->second->create_view(v);
        // if we are not committing now then use NoVersion to deserialise
        // otherwise the view will be considered as having a committed
        // version
        auto deserialise_version = (commit ? v : NoVersion);
        if (!view->deserialise(*d, deserialise_version))
        {
          LOG_FAIL_FMT(
            "Could not deserialise Tx for map {} at version {}",
            map_name,
            deserialise_version);
          return DeserialiseSuccess::FAILED;
        }

        views[map_name] = {search->second.get(),
                           std::unique_ptr<AbstractTxView>(view)};
      }

      if (!d->end())
      {
        LOG_FAIL_FMT("Unexpected content in Tx at version {}", v);
        return DeserialiseSuccess::FAILED;
      }

      auto success = DeserialiseSuccess::PASS;

      if (commit)
      {
        success = commit_deserialised(views, v);
        if (success == DeserialiseSuccess::FAILED)
        {
          return success;
        }
        auto h = get_history();
        if (h)
        {
          auto search = views.find("ccf.signatures");
          if (search != views.end())
          {
            // Transactions containing a signature must only contain
            // a signature and must be verified
            if (views.size() > 1)
            {
              LOG_FAIL_FMT(
                "Unexpected contents in signature transaction {}", v);
              return DeserialiseSuccess::FAILED;
            }

            if (!h->verify(term))
            {
              LOG_FAIL_FMT("Signature in transaction {} failed to verify", v);
              return DeserialiseSuccess::FAILED;
            }
            success = DeserialiseSuccess::PASS_SIGNATURE;
          }

          h->append(data.data(), data.size());
        }
      }
      else
      {
        // Transactions containing a pre prepare or a pbft request should not
        // contain anything else
        if (views.size() > 1)
        {
          LOG_FAIL_FMT("Unexpected contents in pbft transaction {}", v);
          return DeserialiseSuccess::FAILED;
        }

        if (views.find("ccf.pbft.preprepares") != views.end())
        {
          success = DeserialiseSuccess::PASS_PRE_PREPARE;
        }
        else if (views.find("ccf.pbft.newviews") != views.end())
        {
          success = DeserialiseSuccess::PASS_NEW_VIEW;
        }
        else if (views.find("ccf.pbft.requests") == views.end())
        {
          // we have deserialised an entry that didn't belong to the pbft
          // requests, nor the pbft new views, nor the pbft pre prepares table
          return DeserialiseSuccess::FAILED;
        }
      }

      if (tx)
      {
        tx->set_view_list(views);
      }

      return success;
    }

    DeserialiseSuccess deserialise(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr) override
    {
      return deserialise_views(data, public_only, term);
    }

    bool operator==(const Store& that) const
    {
      // Only used for debugging, not thread safe.
      if (version != that.version)
        return false;

      if (maps.size() != that.maps.size())
        return false;

      for (auto it = maps.begin(); it != maps.end(); ++it)
      {
        auto search = that.maps.find(it->first);

        if (search == that.maps.end())
          return false;

        if (*it->second != *search->second)
          return false;
      }

      return true;
    }

    bool operator!=(const Store& that) const
    {
      // Only used for debugging, not thread safe.
      return !(*this == that);
    }

    Version current_version() override
    {
      // Must lock in case the version is being incremented.
      std::lock_guard<SpinLock> vguard(version_lock);
      return version;
    }

    Version commit_version() override
    {
      // Must lock in case the store is being compacted.
      std::lock_guard<SpinLock> vguard(version_lock);
      return compacted;
    }

    CommitSuccess commit(
      Version version, PendingTx pending_tx, bool globally_committable) override
    {
      auto r = get_consensus();
      if (!r)
        return CommitSuccess::OK;

      LOG_DEBUG_FMT(
        "Store::commit {}{}",
        version,
        (globally_committable ? " globally_committable" : ""));

      BatchVector batch;
      Version previous_last_replicated = 0;
      Version next_last_replicated = 0;
      Version previous_rollback_count = 0;

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        if (globally_committable && version > last_committable)
          last_committable = version;

        pending_txs.insert(
          {version,
           std::make_pair(std::move(pending_tx), globally_committable)});

        auto h = get_history();
        auto c = get_consensus();

        for (Version offset = 1; true; ++offset)
        {
          auto search = pending_txs.find(last_replicated + offset);
          if (search == pending_txs.end())
            break;

          auto& [pending_tx_, committable_] = search->second;
          auto [success_, reqid, data_] = pending_tx_();
          auto data_shared =
            std::make_shared<std::vector<uint8_t>>(std::move(data_));

          // NB: this cannot happen currently. Regular Tx only make it here if
          // they did succeed, and signatures cannot conflict because they
          // execute in order with a read_version that's version - 1, so even
          // two contiguous signatures are fine
          if (success_ != CommitSuccess::OK)
            LOG_DEBUG_FMT("Failed Tx commit {}", last_replicated + offset);

          if (h)
          {
            h->add_pending(reqid, version, data_shared);
          }

          LOG_DEBUG_FMT(
            "Batching {} ({})", last_replicated + offset, data_shared->size());
          batch.emplace_back(
            last_replicated + offset, data_shared, committable_);
          pending_txs.erase(search);
        }

        if (batch.size() == 0)
          return CommitSuccess::OK;

        previous_rollback_count = rollback_count;
        previous_last_replicated = last_replicated;
        next_last_replicated = last_replicated + batch.size();
      }

      if (r->replicate(batch))
      {
        std::lock_guard<SpinLock> vguard(version_lock);
        if (
          last_replicated == previous_last_replicated &&
          previous_rollback_count == rollback_count)
        {
          last_replicated = next_last_replicated;
        }
        return CommitSuccess::OK;
      }
      else
      {
        LOG_DEBUG_FMT("Failed to replicate");
        return CommitSuccess::NO_REPLICATE;
      }
    }

    Version next_version() override
    {
      std::lock_guard<SpinLock> vguard(version_lock);

      // Get the next global version. If we would go negative, wrap to 0.
      ++version;

      if (version < 0)
        version = 0;

      return version;
    }

    size_t commit_gap() override
    {
      std::lock_guard<SpinLock> vguard(version_lock);
      return version - last_committable;
    }

    void clear()
    {
      std::lock_guard<SpinLock> mguard(maps_lock);

      // This deletes the entire content of all maps in the store.
      for (auto& map : maps)
        map.second->lock();

      for (auto& map : maps)
        map.second->clear();

      for (auto& map : maps)
        map.second->unlock();

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        version = 0;
        compacted = 0;
        last_replicated = 0;
        last_committable = 0;
        rollback_count = 0;
        pending_txs.clear();
      }
    }

    /** This is only safe in very restricted circumstances, and is only
     * meant to be used during catastrophic recovery, between a KV
     * with public-state only and a KV with full state, to swap in the
     * private state from the latter into the former.
     *
     * It's also important to note that swapping in private state
     * may result in previously uncompacted writes becoming effectively
     * compacted, from a user's perspective (they would not be internally
     * compacted until the next compact() however). So it is important to
     * make sure that the private state being swapped in is fully compacted
     * before the swap.
     **/
    void swap_private_maps(Store& store)
    {
      std::lock_guard<SpinLock> this_maps_guard(maps_lock);
      std::lock_guard<SpinLock> other_maps_guard(store.maps_lock);

      using MapEntry = std::tuple<std::string, AbstractMap*, AbstractMap*>;
      std::vector<MapEntry> entries;

      for (auto& [name, map] : maps)
      {
        if (map->get_security_domain() == SecurityDomain::PRIVATE)
        {
          map->lock();
          entries.emplace_back(name, map.get(), nullptr);
        }
      }

      auto entry = entries.begin();
      for (auto& [name, map] : store.maps)
      {
        if (map->get_security_domain() == SecurityDomain::PRIVATE)
        {
          if (entry == entries.end())
            throw std::logic_error(
              "Private map list mismatch during swap, " + name + " not found");

          if (std::get<0>(*entry) != name)
            throw std::logic_error(
              "Private map list mismatch during swap, " + std::get<0>(*entry) +
              " != " + name);

          map->lock();
          std::get<2>(*entry) = map.get();

          ++entry;
        }
      }

      if (entry != entries.end())
      {
        throw std::logic_error(
          "Private map list mismatch during swap, missing at least " +
          std::get<0>(*entry));
      }

      for (auto& [name, lhs, rhs] : entries)
      {
        lhs->swap(rhs);
      }

      for (auto& [name, lhs, rhs] : entries)
      {
        lhs->unlock();
        rhs->unlock();
      }
    }
  };
}