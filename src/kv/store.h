// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_deprecated.h"
#include "ds/ccf_exception.h"
#include "kv_serialiser.h"
#include "kv_types.h"
#include "map.h"
#include "node/entities.h"
#include "node/progress_tracker.h"
#include "node/signatures.h"
#include "snapshot.h"
#include "tx.h"
#include "view_containers.h"

#include <fmt/format.h>

namespace kv
{
  class Store : public AbstractStore
  {
  private:
    // All collections of Map must be ordered so that we lock their contained
    // maps in a stable order. The order here is by map name. The version
    // indicates the version at which the Map was created.
    using Maps = std::
      map<std::string, std::pair<kv::Version, std::shared_ptr<untyped::Map>>>;
    Maps maps;

    // Store the Defs created by calls to create(), so we can still return &s to
    // match the old API. Doesn't create a real map! Just an association between
    // the types and name
    using MapDefs = std::map<std::string, std::shared_ptr<NamedMap>>;
    MapDefs map_defs;

    using Hooks = std::map<std::string, kv::untyped::Map::CommitHook>;
    Hooks local_hooks;
    Hooks global_hooks;

    std::shared_ptr<Consensus> consensus = nullptr;
    std::shared_ptr<TxHistory> history = nullptr;
    std::shared_ptr<ccf::ProgressTracker> progress_tracker = nullptr;
    EncryptorPtr encryptor = nullptr;
    Version version = 0;
    Version compacted = 0;
    Term term = 0;

    SpinLock maps_lock;
    SpinLock version_lock;

    std::unordered_map<Version, std::pair<PendingTx, bool>> pending_txs;
    Version last_replicated = 0;
    Version last_committable = 0;
    Version rollback_count = 0;
    kv::ReplicateType replicate_type = kv::ReplicateType::ALL;
    std::unordered_set<std::string> replicated_tables;

    // Generally we will only accept deserialised views if they are contiguous -
    // at Version N we reject everything but N+1. The exception is when a Store
    // is used for historical queries, where it may deserialise arbitrary
    // transactions. In this case the Store is a useful container for a set of
    // Tables, but its versioning invariants are ignored.
    const bool strict_versions = true;

    DeserialiseSuccess commit_deserialised(
      OrderedViews& views, Version& v, const MapCollection& new_maps)
    {
      auto c = apply_views(
        views, [v]() { return v; }, new_maps);
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

    bool has_map_internal(const std::string& name)
    {
      auto search = maps.find(name);
      if (search != maps.end())
        return true;

      return false;
    }

  public:
    Store(bool strict_versions_ = true) : strict_versions(strict_versions_) {}

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

    std::shared_ptr<ccf::ProgressTracker> get_progress_tracker()
    {
      return progress_tracker;
    }

    void set_progress_tracker(
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_)
    {
      progress_tracker = progress_tracker_;
    }

    void set_encryptor(const EncryptorPtr& encryptor_)
    {
      encryptor = encryptor_;
    }

    EncryptorPtr get_encryptor() override
    {
      return encryptor;
    }

    template <class K, class V>
    CCF_DEPRECATED(
      "SecurityDomain should not be passed explicitly, but encoded in the "
      "map's name. 'public:' prefix indicates a PUBLIC table, all others are "
      "PRIVATE")
    Map<K, V>& create(const std::string& name, SecurityDomain security_domain)
    {
      return create<Map<K, V>>(name, security_domain);
    }

    template <class M>
    CCF_DEPRECATED(
      "SecurityDomain should not be passed explicitly, but encoded in the "
      "map's name. 'public:' prefix indicates a PUBLIC table, all others are "
      "PRIVATE")
    M& create(const std::string& name, SecurityDomain security_domain)
    {
      if (has_map_internal(name))
        throw std::logic_error(fmt::format("Map '{}' already exists", name));

      const auto [sec_dom, acc_cat] = kv::parse_map_name(name);
      if (sec_dom != security_domain)
      {
        throw std::logic_error(fmt::format(
          "Map '{}' cannot be created with the requested SecurityDomain "
          "(public maps must begin with public: prefix)",
          name));
      }

      return create<M>(name);
    }

    template <class K, class V>
    CCF_DEPRECATED(
      "Maps do not need to be explicitly created from a Store. They will be "
      "created on-demand when they are used by a Tx, and can be instantiated "
      "anywhere as kv::Map<K, V> my_map(my_map_name);")
    Map<K, V>& create(const std::string& name)
    {
      return create<Map<K, V>>(name);
    }

    template <class M>
    CCF_DEPRECATED(
      "Maps do not need to be explicitly created from a Store. They will be "
      "created on-demand when they are used by a Tx, and can be instantiated "
      "anywhere as kv::Map<K, V> my_map(my_map_name);")
    M& create(const std::string& name)
    {
      std::lock_guard<SpinLock> mguard(maps_lock);

      const auto it = map_defs.find(name);
      if (it != map_defs.end())
      {
        throw std::logic_error("Map already exists");
      }

      auto result = std::make_shared<M>(name);
      map_defs[name] = result;
      return *result;
    }

    /** Get a map by name, iff it exists at the given version.
     *
     * This means a prior transaction must have created the map, and
     * successfully committed at a version <= v. If this has not happened (the
     * map has never been created, or never been committed, or committed at a
     * later version) this will return nullptr.
     *
     * @param v Version at which the map must exist
     * @param map_name Name of requested map
     *
     * @return Abstract shared-owning pointer to requested map, or nullptr if no
     * such map exists
     */
    std::shared_ptr<AbstractMap> get_map(
      kv::Version v, const std::string& map_name) override
    {
      auto search = maps.find(map_name);
      if (search != maps.end())
      {
        const auto& [map_creation_version, map_ptr] = search->second;
        if (v >= map_creation_version || map_creation_version == NoVersion)
        {
          return map_ptr;
        }
      }

      return nullptr;
    }

    /** Transfer ownership of a dynamically created map to this Store.
     *
     * Should be called as part of the commit process, once a transaction is
     * known to be conflict-free and has been assigned a unique Version. This
     * publishes dynamically created Maps so they can be retrieved via get_map
     * in future transactions.
     *
     * @param v Version at which map is being committed/created
     * @param map Map to add
     */
    void add_dynamic_map(
      kv::Version v, const std::shared_ptr<AbstractMap>& map_) override
    {
      auto map = std::dynamic_pointer_cast<kv::untyped::Map>(map_);
      if (map == nullptr)
      {
        throw std::logic_error(fmt::format(
          "Can't add dynamic map - {} is not of expected type",
          map_->get_name()));
      }

      const auto map_name = map->get_name();
      if (get_map(v, map_name) != nullptr)
      {
        throw std::logic_error(fmt::format(
          "Can't add dynamic map - already have a map named {}", map_name));
      }

      maps[map_name] = std::make_pair(v, map);

      {
        // If we have any hooks for the given map name, set them on this new map
        const auto local_it = local_hooks.find(map_name);
        if (local_it != local_hooks.end())
        {
          map->set_local_hook(local_it->second);
        }

        const auto global_it = global_hooks.find(map_name);
        if (global_it != global_hooks.end())
        {
          map->set_global_hook(global_it->second);
        }
      }
    }

    bool is_map_replicated(const std::string& name) override
    {
      switch (replicate_type)
      {
        case (kv::ReplicateType::ALL):
        {
          return true;
        }

        case (kv::ReplicateType::NONE):
        {
          return false;
        }

        case (kv::ReplicateType::SOME):
        {
          return replicated_tables.find(name) != replicated_tables.end();
        }

        default:
        {
          throw std::logic_error("Unhandled ReplicateType value");
        }
      }
    }

    std::unique_ptr<AbstractSnapshot> snapshot(Version v) override
    {
      if (v < commit_version())
      {
        throw std::logic_error(fmt::format(
          "Cannot snapshot at version {} which is earlier than committed "
          "version {} ",
          v,
          commit_version()));
      }

      if (v > current_version())
      {
        throw std::logic_error(fmt::format(
          "Cannot snapshot at version {} which is later than current "
          "version {} ",
          v,
          current_version()));
      }

      auto snapshot = std::make_unique<StoreSnapshot>(v);

      {
        std::lock_guard<SpinLock> mguard(maps_lock);

        for (auto& it : maps)
        {
          auto& [_, map] = it.second;
          map->lock();
        }

        for (auto& it : maps)
        {
          auto& [_, map] = it.second;
          snapshot->add_map_snapshot(map->snapshot(v));
        }

        auto h = get_history();
        if (h)
        {
          snapshot->add_hash_at_snapshot(h->get_raw_leaf(v));
        }

        auto c = get_consensus();
        if (c)
        {
          snapshot->add_view_history(c->get_view_history(v));
        }

        for (auto& it : maps)
        {
          auto& [_, map] = it.second;
          map->unlock();
        }
      }

      return snapshot;
    }

    std::vector<uint8_t> serialise_snapshot(
      std::unique_ptr<AbstractSnapshot> snapshot) override
    {
      auto e = get_encryptor();
      return snapshot->serialise(e);
    }

    DeserialiseSuccess deserialise_snapshot(
      const std::vector<uint8_t>& data,
      std::vector<Version>* view_history = nullptr,
      bool public_only = false) override
    {
      auto e = get_encryptor();
      auto d = KvStoreDeserialiser(
        e,
        public_only ? kv::SecurityDomain::PUBLIC :
                      std::optional<kv::SecurityDomain>());

      auto v_ = d.init(data.data(), data.size());
      if (!v_.has_value())
      {
        LOG_FAIL_FMT("Initialisation of deserialise object failed");
        return DeserialiseSuccess::FAILED;
      }
      auto v = v_.value();

      std::lock_guard<SpinLock> mguard(maps_lock);

      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->lock();
      }

      std::vector<uint8_t> hash_at_snapshot;
      auto h = get_history();
      if (h)
      {
        hash_at_snapshot = d.deserialise_raw();
      }

      std::vector<Version> view_history_;
      if (view_history)
      {
        view_history_ = d.deserialise_view_history();
      }

      OrderedViews views;
      MapCollection new_maps;

      for (auto r = d.start_map(); r.has_value(); r = d.start_map())
      {
        const auto map_name = r.value();

        std::shared_ptr<AbstractMap> map = nullptr;

        auto search = maps.find(map_name);
        if (search == maps.end())
        {
          map = std::make_shared<kv::untyped::Map>(
            this,
            map_name,
            get_security_domain(map_name),
            is_map_replicated(map_name));
          new_maps[map_name] = map;
          LOG_DEBUG_FMT(
            "Creating map {} while deserialising snapshot at version {}",
            map_name,
            v);
        }
        else
        {
          map = search->second.second;
        }

        auto view_search = views.find(map_name);
        if (view_search != views.end())
        {
          LOG_FAIL_FMT("Failed to deserialise snapshot at version {}", v);
          LOG_DEBUG_FMT("Multiple writes on map {}", map_name);
          return DeserialiseSuccess::FAILED;
        }

        auto deserialise_snapshot_view = map->deserialise_snapshot(d);

        // Take ownership of the produced view, store it to be committed
        // later
        views[map_name] = {
          map, std::unique_ptr<AbstractTxView>(deserialise_snapshot_view)};
      }

      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->unlock();
      }

      if (!d.end())
      {
        LOG_FAIL_FMT("Unexpected content in snapshot at version {}", v);
        return DeserialiseSuccess::FAILED;
      }

      // Each map is committed at a different version, independently of the
      // overall snapshot version. The commit versions for each map are
      // contained in the snapshot and applied when the snapshot is committed.
      auto r = apply_views(
        views, []() { return NoVersion; }, new_maps);
      if (!r.has_value())
      {
        LOG_FAIL_FMT("Failed to commit deserialised snapshot at version {}", v);
        return DeserialiseSuccess::FAILED;
      }

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        version = v;
        last_replicated = v;
        last_committable = v;
      }

      if (h)
      {
        if (!h->init_from_snapshot(hash_at_snapshot))
        {
          return DeserialiseSuccess::FAILED;
        }
      }

      if (view_history)
      {
        *view_history = std::move(view_history_);
      }

      return DeserialiseSuccess::PASS;
    }

    void compact(Version v) override
    {
      // This is called when the store will never be rolled back to any
      // state before the specified version.
      // No transactions can be prepared or committed during compaction.
      std::lock_guard<SpinLock> mguard(maps_lock);

      if (v > current_version())
      {
        return;
      }

      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->lock();
      }

      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->compact(v);
      }

      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->unlock();
      }

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        compacted = v;

        auto h = get_history();
        if (h)
        {
          h->compact(v);
        }

        auto e = get_encryptor();
        if (e)
        {
          e->compact(v);
        }
      }

      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->post_compact();
      }
    }

    void rollback(Version v, std::optional<Term> t = std::nullopt) override
    {
      // This is called to roll the store back to the state it was in
      // at the specified version.
      // No transactions can be prepared or committed during rollback.
      std::lock_guard<SpinLock> mguard(maps_lock);

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        // The term should always be updated on rollback() when passed
        // regardless of whether version needs to be updated or not
        if (t.has_value())
          term = t.value();
        if (v >= version)
          return;
      }

      if (v < commit_version())
      {
        throw std::logic_error(fmt::format(
          "Attempting rollback to {}, earlier than commit version {}",
          v,
          commit_version()));
      }

      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->lock();
      }

      auto it = maps.begin();
      while (it != maps.end())
      {
        auto& [map_creation_version, map] = it->second;
        // Rollback this map whether we're forgetting about it or not. Anyone
        // else still holding it should see it has rolled back
        map->rollback(v);
        if (map_creation_version > v)
        {
          // Map was created more recently; its creation is being forgotten.
          // Erase our knowledge of it
          map->unlock();
          it = maps.erase(it);
        }
        else
        {
          ++it;
        }
      }

      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->unlock();
      }

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

    void set_term(Term t) override
    {
      std::lock_guard<SpinLock> vguard(version_lock);
      term = t;
    }

    DeserialiseSuccess deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term_ = nullptr,
      Version* index_ = nullptr,
      AbstractViewContainer* tx = nullptr,
      ccf::PrimarySignature* sig = nullptr)
    {
      // If we pass in a transaction we don't want to commit, just deserialise
      // and put the views into that transaction.
      // Tread carefully here: at the moment passing in a transaction assumes we
      // are using bft as the consensus
      auto commit = (tx == nullptr);

      // This will return FAILED if the serialised transaction is being
      // applied out of order.
      // Processing transactions locally and also deserialising to the
      // same store will result in a store version mismatch and
      // deserialisation will then fail.
      auto e = get_encryptor();

      auto d = KvStoreDeserialiser(
        e,
        public_only ? kv::SecurityDomain::PUBLIC :
                      std::optional<kv::SecurityDomain>());

      auto v_ = d.init(data.data(), data.size());
      if (!v_.has_value())
      {
        LOG_FAIL_FMT("Initialisation of deserialise object failed");
        return DeserialiseSuccess::FAILED;
      }
      auto v = v_.value();

      // Throw away any local commits that have not propagated via the
      // consensus.
      rollback(v - 1);

      if (strict_versions)
      {
        // Make sure this is the next transaction.
        auto cv = current_version();
        if (cv != (v - 1))
        {
          LOG_FAIL_FMT(
            "Tried to deserialise {} but current_version is {}", v, cv);
          return DeserialiseSuccess::FAILED;
        }
      }

      // Deserialised transactions express read dependencies as versions,
      // rather than with the actual value read. As a result, they don't
      // need snapshot isolation on the map state, and so do not need to
      // lock each of the maps before creating the transaction.
      std::lock_guard<SpinLock> mguard(maps_lock);
      OrderedViews views;
      MapCollection new_maps;

      for (auto r = d.start_map(); r.has_value(); r = d.start_map())
      {
        const auto map_name = r.value();

        auto map = get_map(v, map_name);
        if (map == nullptr)
        {
          auto map_shared = std::make_shared<kv::untyped::Map>(
            this,
            map_name,
            get_security_domain(map_name),
            is_map_replicated(map_name));
          map = map_shared;
          new_maps[map_name] = map_shared;
          LOG_DEBUG_FMT(
            "Creating map {} while deserialising transaction at version {}",
            map_name,
            v);
        }

        auto view_search = views.find(map_name);
        if (view_search != views.end())
        {
          LOG_FAIL_FMT("Failed to deserialise transaction at version {}", v);
          LOG_DEBUG_FMT("Multiple writes on map {}", map_name);
          return DeserialiseSuccess::FAILED;
        }

        auto deserialised_view = map->deserialise(d, v, commit);

        // Take ownership of the produced view, store it to be applied
        // later
        views[map_name] = {map,
                           std::unique_ptr<AbstractTxView>(deserialised_view)};
      }

      if (!d.end())
      {
        LOG_FAIL_FMT("Unexpected content in transaction at version {}", v);
        return DeserialiseSuccess::FAILED;
      }

      auto success = DeserialiseSuccess::PASS;

      if (commit)
      {
        success = commit_deserialised(views, v, new_maps);
        if (success == DeserialiseSuccess::FAILED)
        {
          return success;
        }

        auto h = get_history();

        auto search = views.find(ccf::Tables::SIGNATURES);
        if (search != views.end())
        {
          // Transactions containing a signature must only contain
          // a signature and must be verified
          if (views.size() > 1)
          {
            LOG_FAIL_FMT("Failed to deserialise");
            LOG_DEBUG_FMT("Unexpected contents in signature transaction {}", v);
            return DeserialiseSuccess::FAILED;
          }

          if (h)
          {
            if (!h->verify(term_))
            {
              LOG_FAIL_FMT("Failed to deserialise");
              LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
              return DeserialiseSuccess::FAILED;
            }
          }
          success = DeserialiseSuccess::PASS_SIGNATURE;
        }

        if (h)
        {
          h->append(data.data(), data.size());
        }
      }
      else
      {
        // BFT Transactions should only write to 1 table
        if (views.size() != 1)
        {
          LOG_FAIL_FMT("Failed to deserialise");
          LOG_DEBUG_FMT(
            "Unexpected contents in bft transaction {}, size:{}",
            v,
            views.size());
          return DeserialiseSuccess::FAILED;
        }

        if (views.find(ccf::Tables::SIGNATURES) != views.end())
        {
          success = commit_deserialised(views, v, new_maps);
          if (success == DeserialiseSuccess::FAILED)
          {
            return success;
          }

          auto h = get_history();
          bool result = true;
          if (sig != nullptr)
          {
            auto r = h->verify_and_sign(*sig, term_);
            if (
              r != kv::TxHistory::Result::OK &&
              r != kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK)
            {
              result = false;
            }
          }
          else
          {
            result = h->verify(term_);
          }

          if (!result)
          {
            LOG_FAIL_FMT("Failed to deserialise");
            LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
            throw std::logic_error(
              "Failed to verify signature, view-changes not implemented");
            return DeserialiseSuccess::FAILED;
          }
          h->append(data.data(), data.size());
          success = DeserialiseSuccess::PASS_SIGNATURE;
        }
        else if (views.find(ccf::Tables::BACKUP_SIGNATURES) != views.end())
        {
          success = commit_deserialised(views, v, new_maps);
          if (success == DeserialiseSuccess::FAILED)
          {
            return success;
          }

          kv::TxID tx_id;

          auto r = progress_tracker->receive_backup_signatures(
            tx_id, consensus->node_count(), consensus->is_primary());
          if (r == kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK)
          {
            success = DeserialiseSuccess::PASS_BACKUP_SIGNATURE_SEND_ACK;
          }
          else if (r == kv::TxHistory::Result::OK)
          {
            success = DeserialiseSuccess::PASS_BACKUP_SIGNATURE;
          }
          else
          {
            LOG_FAIL_FMT("receive_backup_signatures Failed");
            LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
            throw std::logic_error(
              "Failed to verify signature, view-changes not implemented");
            return DeserialiseSuccess::FAILED;
          }

          *term_ = tx_id.term;
          *index_ = tx_id.version;

          auto h = get_history();
          h->append(data.data(), data.size());
        }
        else if (views.find(ccf::Tables::NONCES) != views.end())
        {
          success = commit_deserialised(views, v, new_maps);
          if (success == DeserialiseSuccess::FAILED)
          {
            return success;
          }

          auto r = progress_tracker->receive_nonces();
          if (r != kv::TxHistory::Result::OK)
          {
            LOG_FAIL_FMT("receive_nonces Failed");
            throw std::logic_error(
              "Failed to verify nonces, view-changes not implemented");
            return DeserialiseSuccess::FAILED;
          }

          auto h = get_history();
          h->append(data.data(), data.size());
          success = DeserialiseSuccess::PASS_NONCES;
        }
        else if (views.find(ccf::Tables::AFT_REQUESTS) == views.end())
        {
          // we have deserialised an entry that didn't belong to the bft
          // requests nor the signatures table
          LOG_FAIL_FMT(
            "Request contains unexpected table - {}", views.begin()->first);
          CCF_ASSERT_FMT_FAIL(
            "Request contains unexpected table - {}", views.begin()->first);
        }
      }

      if (tx)
      {
        tx->set_view_list(views, term);
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

        auto& [this_v, this_map] = it->second;
        auto& [that_v, that_map] = search->second;

        if (this_v != that_v)
          return false;

        if (*this_map != *that_map)
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
      // Must lock in case the version or term is being incremented.
      std::lock_guard<SpinLock> vguard(version_lock);
      return version;
    }

    TxID current_txid() override
    {
      // Must lock in case the version is being incremented.
      std::lock_guard<SpinLock> vguard(version_lock);
      return {term, version};
    }

    Version commit_version() override
    {
      // Must lock in case the store is being compacted.
      std::lock_guard<SpinLock> vguard(version_lock);
      return compacted;
    }

    CommitSuccess commit(
      const TxID& txid,
      PendingTx&& pending_tx,
      bool globally_committable) override
    {
      auto c = get_consensus();
      if (!c)
      {
        return CommitSuccess::OK;
      }

      LOG_DEBUG_FMT(
        "Store::commit {}{}",
        txid.version,
        (globally_committable ? " globally_committable" : ""));

      BatchVector batch;
      Version previous_last_replicated = 0;
      Version next_last_replicated = 0;
      Version previous_rollback_count = 0;
      kv::Consensus::View replication_view = 0;

      {
        std::lock_guard<SpinLock> vguard(version_lock);
        if (txid.term != term)
        {
          // This can happen when a transaction started before a view change,
          // but tries to commit after the view change is complete.
          LOG_DEBUG_FMT(
            "Want to commit for term {} but term is {}", txid.term, term);

          return CommitSuccess::NO_REPLICATE;
        }

        if (globally_committable && txid.version > last_committable)
          last_committable = txid.version;

        pending_txs.insert(
          {txid.version,
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
            h->add_pending(reqid, txid.version, data_shared);
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

        replication_view = term;
      }

      if (c->replicate(batch, replication_view))
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

    void lock() override
    {
      maps_lock.lock();
    }

    void unlock() override
    {
      maps_lock.unlock();
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

    TxID next_txid() override
    {
      std::lock_guard<SpinLock> vguard(version_lock);

      // Get the next global version. If we would go negative, wrap to 0.
      ++version;
      if (version < 0)
        version = 0;

      return {term, version};
    }

    size_t commit_gap() override
    {
      std::lock_guard<SpinLock> vguard(version_lock);
      return version - last_committable;
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
      {
        const auto source_version = store.current_version();
        const auto target_version = current_version();
        if (source_version > target_version)
        {
          throw std::runtime_error(fmt::format(
            "Invalid call to swap_private_maps. Source is at version {} while "
            "target is at {}",
            source_version,
            target_version));
        }
      }

      std::lock_guard<SpinLock> this_maps_guard(maps_lock);
      std::lock_guard<SpinLock> other_maps_guard(store.maps_lock);

      // Each entry is (Name, MyMap, TheirMap)
      using MapEntry = std::tuple<std::string, AbstractMap*, AbstractMap*>;
      std::vector<MapEntry> entries;

      // Get the list of private maps from the source store
      for (auto& [name, pair] : store.maps)
      {
        auto& [_, map] = pair;
        if (map->get_security_domain() == SecurityDomain::PRIVATE)
        {
          map->lock();
          entries.emplace_back(name, nullptr, map.get());
        }
      }

      // For each source map, either create it or, where it already exists,
      // confirm it is PRIVATE. Lock it and store it in entries
      auto entry = entries.begin();
      while (entry != entries.end())
      {
        const auto& [name, _, their_map] = *entry;
        std::shared_ptr<AbstractMap> map = nullptr;
        const auto it = maps.find(name);
        if (it == maps.end())
        {
          // NB: We lose the creation version from the original map, but assume
          // it is irrelevant - its creation should no longer be at risk of
          // rollback
          auto new_map = std::make_pair(
            NoVersion,
            std::make_shared<kv::untyped::Map>(
              this, name, SecurityDomain::PRIVATE, is_map_replicated(name)));
          maps[name] = new_map;
          map = new_map.second;
        }
        else
        {
          map = it->second.second;
          if (map->get_security_domain() != SecurityDomain::PRIVATE)
          {
            throw std::logic_error(fmt::format(
              "Swap mismatch - map {} is private in source but not in target",
              name));
          }
        }

        std::get<1>(*entry) = map.get();
        map->lock();
        ++entry;
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

    void set_local_hook(
      const std::string& map_name, const kv::untyped::Map::CommitHook& hook)
    {
      local_hooks[map_name] = hook;

      const auto it = maps.find(map_name);
      if (it != maps.end())
      {
        it->second.second->set_local_hook(hook);
      }
    }

    void unset_local_hook(const std::string& map_name)
    {
      local_hooks.erase(map_name);

      const auto it = maps.find(map_name);
      if (it != maps.end())
      {
        it->second.second->unset_local_hook();
      }
    }

    void set_global_hook(
      const std::string& map_name, const kv::untyped::Map::CommitHook& hook)
    {
      global_hooks[map_name] = hook;

      const auto it = maps.find(map_name);
      if (it != maps.end())
      {
       it->second.second->set_global_hook(hook);
      }
    }

    void unset_global_hook(const std::string& map_name)
    {
      global_hooks.erase(map_name);

      const auto it = maps.find(map_name);
      if (it != maps.end())
      {
        it->second.second->unset_global_hook();
      }
    }

    ReadOnlyTx create_read_only_tx()
    {
      return ReadOnlyTx(this);
    }

    Tx create_tx()
    {
      return Tx(this);
    }

    ReservedTx create_reserved_tx(Version v)
    {
      return ReservedTx(this, v);
    }
  };
}