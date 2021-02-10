// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apply_changes.h"
#include "deserialise.h"
#include "ds/ccf_exception.h"
#include "kv_serialiser.h"
#include "kv_types.h"
#include "map.h"
#include "node/entities.h"
#include "node/progress_tracker.h"
#include "node/signatures.h"
#include "snapshot.h"
#include "tx.h"

#include <fmt/format.h>

namespace kv
{
  class StoreState
  {
  protected:
    // All collections of Map must be ordered so that we lock their contained
    // maps in a stable order. The order here is by map name. The version
    // indicates the version at which the Map was created.
    using Maps = std::
      map<std::string, std::pair<kv::Version, std::shared_ptr<untyped::Map>>>;
    SpinLock maps_lock;
    Maps maps;

    SpinLock version_lock;
    Version version = 0;
    Version compacted = 0;
    Term term = 0;
    Version last_replicated = 0;
    Version last_committable = 0;
    Version rollback_count = 0;

    std::unordered_map<Version, std::pair<std::unique_ptr<PendingTx>, bool>>
      pending_txs;

  public:
    void clear()
    {
      std::lock_guard<SpinLock> mguard(maps_lock);
      std::lock_guard<SpinLock> vguard(version_lock);

      maps.clear();
      pending_txs.clear();

      version = 0;
      compacted = 0;
      term = 0;

      last_replicated = 0;
      last_committable = 0;
      rollback_count = 0;
    }
  };

  class Store : public AbstractStore,
                public StoreState,
                public ExecutionWrapperStore
  {
  private:
    using Hooks = std::map<std::string, kv::untyped::Map::CommitHook>;
    using MapHooks = std::map<std::string, kv::untyped::Map::MapHook>;
    Hooks global_hooks;
    MapHooks map_hooks;

    std::shared_ptr<Consensus> consensus = nullptr;
    std::shared_ptr<TxHistory> history = nullptr;
    std::shared_ptr<ccf::ProgressTracker> progress_tracker = nullptr;
    EncryptorPtr encryptor = nullptr;

    kv::ReplicateType replicate_type = kv::ReplicateType::ALL;
    std::unordered_set<std::string> replicated_tables;

    // Generally we will only accept deserialised views if they are contiguous -
    // at Version N we reject everything but N+1. The exception is when a Store
    // is used for historical queries, where it may deserialise arbitrary
    // transactions. In this case the Store is a useful container for a set of
    // Tables, but its versioning invariants are ignored.
    const bool strict_versions = true;

    // If true, use historical ledger secrets to deserialise entries
    const bool is_historical = false;

    bool commit_deserialised(
      OrderedChanges& changes,
      Version& v,
      const MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks) override
    {
      auto c = apply_changes(
        changes, [v]() { return v; }, hooks, new_maps);
      if (!c.has_value())
      {
        LOG_FAIL_FMT("Failed to commit deserialised Tx at version {}", v);
        return false;
      }
      {
        std::lock_guard<SpinLock> vguard(version_lock);
        version = v;
        last_replicated = version;
      }
      return true;
    }

    bool has_map_internal(const std::string& name)
    {
      auto search = maps.find(name);
      if (search != maps.end())
        return true;

      return false;
    }

  public:
    Store(bool strict_versions_ = true, bool is_historical_ = false) :
      strict_versions(strict_versions_),
      is_historical(is_historical_)
    {}

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
      return get_map_internal(v, map_name);
    }

    std::shared_ptr<kv::untyped::Map> get_map_internal(
      kv::Version v, const std::string& map_name)
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

      LOG_DEBUG_FMT("Adding newly created map '{}' at version {}", map_name, v);
      maps[map_name] = std::make_pair(v, map);

      {
        // If we have any hooks for the given map name, set them on this new map
        const auto global_it = global_hooks.find(map_name);
        if (global_it != global_hooks.end())
        {
          map->set_global_hook(global_it->second);
        }

        const auto map_it = map_hooks.find(map_name);
        if (map_it != map_hooks.end())
        {
          map->set_map_hook(map_it->second);
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

    ApplyResult deserialise_snapshot(
      const std::vector<uint8_t>& data,
      kv::ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history = nullptr,
      bool public_only = false) override
    {
      auto e = get_encryptor();
      auto d = KvStoreDeserialiser(
        e,
        public_only ? kv::SecurityDomain::PUBLIC :
                      std::optional<kv::SecurityDomain>());

      auto v_ = d.init(data.data(), data.size(), is_historical);
      if (!v_.has_value())
      {
        LOG_FAIL_FMT("Initialisation of deserialise object failed");
        return ApplyResult::FAIL;
      }
      auto [v, _] = v_.value();

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

      OrderedChanges changes;
      MapCollection new_maps;

      for (auto r = d.start_map(); r.has_value(); r = d.start_map())
      {
        const auto map_name = r.value();

        std::shared_ptr<kv::untyped::Map> map = nullptr;

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

        auto changes_search = changes.find(map_name);
        if (changes_search != changes.end())
        {
          LOG_FAIL_FMT("Failed to deserialise snapshot at version {}", v);
          LOG_DEBUG_FMT("Multiple writes on map {}", map_name);
          return ApplyResult::FAIL;
        }

        auto deserialised_snapshot_changes =
          map->deserialise_snapshot_changes(d);

        // Take ownership of the produced change set, store it to be committed
        // later
        changes[map_name] = {map, std::move(deserialised_snapshot_changes)};
      }

      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->unlock();
      }

      if (!d.end())
      {
        LOG_FAIL_FMT("Unexpected content in snapshot at version {}", v);
        return ApplyResult::FAIL;
      }

      // Each map is committed at a different version, independently of the
      // overall snapshot version. The commit versions for each map are
      // contained in the snapshot and applied when the snapshot is committed.
      auto r = apply_changes(
        changes, []() { return NoVersion; }, hooks, new_maps);
      if (!r.has_value())
      {
        LOG_FAIL_FMT("Failed to commit deserialised snapshot at version {}", v);
        return ApplyResult::FAIL;
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
          return ApplyResult::FAIL;
        }
      }

      if (view_history)
      {
        *view_history = std::move(view_history_);
      }

      return ApplyResult::PASS;
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
        if (v < compacted)
        {
          throw std::logic_error(fmt::format(
            "Attempting rollback to {}, earlier than commit version {}",
            v,
            compacted));
        }

        // The term should always be updated on rollback() when passed
        // regardless of whether version needs to be updated or not
        if (t.has_value())
        {
          term = t.value();
        }
        // History must be informed of the term change, even if no
        // actual rollback is required
        auto h = get_history();
        if (h)
        {
          h->rollback(v, term);
        }

        if (v >= version)
        {
          return;
        }

        version = v;
        last_replicated = v;
        last_committable = v;
        rollback_count++;
        pending_txs.clear();
        auto e = get_encryptor();
        if (e)
        {
          e->rollback(v);
        }
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
    }

    void set_term(Term t) override
    {
      std::lock_guard<SpinLock> vguard(version_lock);
      term = t;
      auto h = get_history();
      if (h)
      {
        h->set_term(term);
      }
    }

    bool fill_maps(
      const std::vector<uint8_t>& data,
      bool public_only,
      kv::Version& v,
      OrderedChanges& changes,
      MapCollection& new_maps,
      bool ignore_strict_versions = false) override
    {
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

      auto v_ = d.init(data.data(), data.size(), is_historical);
      if (!v_.has_value())
      {
        LOG_FAIL_FMT("Initialisation of deserialise object failed");
        return false;
      }
      std::tie(v, std::ignore) = v_.value();

      // Throw away any local commits that have not propagated via the
      // consensus.
      rollback(v - 1);

      if (strict_versions && !ignore_strict_versions)
      {
        // Make sure this is the next transaction.
        auto cv = current_version();
        if (cv != (v - 1))
        {
          LOG_FAIL_FMT(
            "Tried to deserialise {} but current_version is {}", v, cv);
          return false;
        }
      }

      // Deserialised transactions express read dependencies as versions,
      // rather than with the actual value read. As a result, they don't
      // need snapshot isolation on the map state, and so do not need to
      // lock each of the maps before creating the transaction.
      std::lock_guard<SpinLock> mguard(maps_lock);

      for (auto r = d.start_map(); r.has_value(); r = d.start_map())
      {
        const auto map_name = r.value();

        auto map = get_map_internal(v, map_name);
        if (map == nullptr)
        {
          auto new_map = std::make_shared<kv::untyped::Map>(
            this,
            map_name,
            get_security_domain(map_name),
            is_map_replicated(map_name));
          map = new_map;
          new_maps[map_name] = new_map;
          LOG_DEBUG_FMT(
            "Creating map '{}' while deserialising transaction at version {}",
            map_name,
            v);
        }

        auto change_search = changes.find(map_name);
        if (change_search != changes.end())
        {
          LOG_FAIL_FMT("Failed to deserialise transaction at version {}", v);
          LOG_DEBUG_FMT("Multiple writes on map {}", map_name);
          return false;
        }

        auto deserialised_changes = map->deserialise_changes(d, v);

        // Take ownership of the produced change set, store it to be applied
        // later
        changes[map_name] =
          kv::MapChanges{map, std::move(deserialised_changes)};
      }

      if (!d.end())
      {
        LOG_FAIL_FMT("Unexpected content in transaction at version {}", v);
        return false;
      }
      return true;
    }

    std::unique_ptr<kv::AbstractExecutionWrapper> apply(
      const std::vector<uint8_t> data,
      ConsensusType consensus_type,
      bool public_only = false) override
    {
      if (consensus_type == ConsensusType::CFT)
      {
        auto exec = std::make_unique<CFTExecutionWrapper>(
          this, get_history(), std::move(data), public_only);
        return exec;
      }
      else
      {
        kv::Version v;
        OrderedChanges changes;
        MapCollection new_maps;
        if (!fill_maps(data, public_only, v, changes, new_maps, true))
        {
          return nullptr;
        }

        // BFT Transactions should only write to 1 table
        if (changes.size() != 1)
        {
          LOG_FAIL_FMT("Failed to deserialise");
          LOG_DEBUG_FMT(
            "Unexpected contents in bft transaction {}, size:{}",
            v,
            changes.size());
          return nullptr;
        }

        std::unique_ptr<BFTExecutionWrapper> exec;

        if (changes.find(ccf::Tables::SIGNATURES) != changes.end())
        {
          exec = std::make_unique<SignatureBFTExec>(
            this,
            get_history(),
            std::move(data),
            public_only,
            v,
            std::move(changes),
            std::move(new_maps));
        }
        else if (changes.find(ccf::Tables::BACKUP_SIGNATURES) != changes.end())
        {
          exec = std::make_unique<BackupSignatureBFTExec>(
            this,
            get_history(),
            get_progress_tracker(),
            get_consensus(),
            std::move(data),
            public_only,
            v,
            std::move(changes),
            std::move(new_maps));
        }
        else if (changes.find(ccf::Tables::NONCES) != changes.end())
        {
          exec = std::make_unique<NoncesBFTExec>(
            this,
            get_history(),
            get_progress_tracker(),
            std::move(data),
            public_only,
            v,
            std::move(changes),
            std::move(new_maps));
        }
        else if (changes.find(ccf::Tables::NEW_VIEWS) != changes.end())
        {
          exec = std::make_unique<NewViewBFTExec>(
            this,
            get_history(),
            get_progress_tracker(),
            get_consensus(),
            std::move(data),
            public_only,
            v,
            std::move(changes),
            std::move(new_maps));
        }
        else if (changes.find(ccf::Tables::AFT_REQUESTS) != changes.end())
        {
          exec = std::make_unique<TxBFTExec>(
            this,
            get_history(),
            std::move(data),
            public_only,
            std::make_unique<Tx>(this),
            v,
            std::move(changes),
            std::move(new_maps));
        }
        else
        {
          // we have deserialised an entry that didn't belong to the bft
          // requests nor the signatures table
          LOG_FAIL_FMT(
            "Request contains unexpected table - {}", changes.begin()->first);
          CCF_ASSERT_FMT_FAIL(
            "Request contains unexpected table - {}", changes.begin()->first);
        }
        return exec;
      }
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

    CommitResult commit(
      const TxID& txid,
      std::unique_ptr<PendingTx> pending_tx,
      bool globally_committable) override
    {
      auto c = get_consensus();
      if (!c)
      {
        return CommitResult::SUCCESS;
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

          return CommitResult::FAIL_NO_REPLICATE;
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
          auto [success_, reqid, data_, hooks_] = pending_tx_->call();
          auto data_shared =
            std::make_shared<std::vector<uint8_t>>(std::move(data_));
          auto hooks_shared =
            std::make_shared<kv::ConsensusHookPtrs>(std::move(hooks_));

          // NB: this cannot happen currently. Regular Tx only make it here if
          // they did succeed, and signatures cannot conflict because they
          // execute in order with a read_version that's version - 1, so even
          // two contiguous signatures are fine
          if (success_ != CommitResult::SUCCESS)
            LOG_DEBUG_FMT("Failed Tx commit {}", last_replicated + offset);

          if (h)
          {
            h->append(*data_shared);
          }

          LOG_DEBUG_FMT(
            "Batching {} ({})", last_replicated + offset, data_shared->size());

          batch.emplace_back(
            last_replicated + offset, data_shared, committable_, hooks_shared);
          pending_txs.erase(search);
        }

        if (batch.size() == 0)
          return CommitResult::SUCCESS;

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
        return CommitResult::SUCCESS;
      }
      else
      {
        LOG_DEBUG_FMT("Failed to replicate");
        return CommitResult::FAIL_NO_REPLICATE;
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

    void set_map_hook(
      const std::string& map_name, const kv::untyped::Map::MapHook& hook)
    {
      map_hooks[map_name] = hook;

      const auto it = maps.find(map_name);
      if (it != maps.end())
      {
        it->second.second->set_map_hook(hook);
      }
    }

    void unset_map_hook(const std::string& map_name)
    {
      map_hooks.erase(map_name);

      const auto it = maps.find(map_name);
      if (it != maps.end())
      {
        it->second.second->unset_map_hook();
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
