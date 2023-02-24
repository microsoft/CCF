// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apply_changes.h"
#include "ccf/ds/ccf_exception.h"
#include "ccf/kv/read_only_store.h"
#include "ccf/pal/locking.h"
#include "consensus/aft/request.h"
#include "deserialise.h"
#include "kv/committable_tx.h"
#include "kv/snapshot.h"
#include "kv/untyped_map.h"
#include "kv_serialiser.h"
#include "kv_types.h"

#define FMT_HEADER_ONLY
#include <atomic>
#include <fmt/format.h>
#include <memory>

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
    ccf::pal::Mutex maps_lock;
    Maps maps;

    ccf::pal::Mutex version_lock;
    std::atomic<Version> version = 0;
    Version last_new_map = kv::NoVersion;
    std::atomic<Version> compacted = 0;

    // Calls to Store::commit are made atomic by taking this lock.
    ccf::pal::Mutex commit_lock;

    // Term at which write future transactions should be committed.
    std::atomic<Term> term_of_next_version = 0;

    // Term at which the last entry was committed. Further transactions
    // should read in that term. Note that it is assumed that the history of
    // terms of past transactions is kept track of by and specified by the
    // caller on rollback
    Term term_of_last_version = 0;

    Version last_replicated = 0;
    // Version of the latest committable entry committed in this term and by
    // _this_ store.
    Version last_committable = 0;

    Version rollback_count = 0;

    std::unordered_map<Version, std::tuple<std::unique_ptr<PendingTx>, bool>>
      pending_txs;

  public:
    void clear()
    {
      std::lock_guard<ccf::pal::Mutex> mguard(maps_lock);
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);

      maps.clear();
      pending_txs.clear();

      version = 0;
      last_new_map = kv::NoVersion;
      compacted = 0;
      term_of_next_version = 0;
      term_of_last_version = 0;

      last_replicated = 0;
      last_committable = 0;
      rollback_count = 0;
    }
  };

  class Store : public AbstractStore,
                public StoreState,
                public ExecutionWrapperStore,
                public ReadOnlyStore
  {
  private:
    using Hooks = std::map<std::string, kv::untyped::Map::CommitHook>;
    using MapHooks = std::map<std::string, kv::untyped::Map::MapHook>;
    Hooks global_hooks;
    MapHooks map_hooks;

    std::shared_ptr<Consensus> consensus = nullptr;
    std::shared_ptr<TxHistory> history = nullptr;
    EncryptorPtr encryptor = nullptr;
    SnapshotterPtr snapshotter = nullptr;

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

    // Ledger entry header flags
    uint8_t flags = 0;

    bool commit_deserialised(
      OrderedChanges& changes,
      Version v,
      Term term,
      const MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks,
      bool track_deletes_on_missing_keys) override
    {
      auto c = apply_changes(
        changes,
        [v](bool) { return std::make_tuple(v, v - 1); },
        hooks,
        new_maps,
        std::nullopt,
        false,
        track_deletes_on_missing_keys);
      if (!c.has_value())
      {
        LOG_FAIL_FMT("Failed to commit deserialised Tx at version {}", v);
        return false;
      }
      {
        std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
        version = v;
        last_replicated = version;
        term_of_last_version = term;
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

    Version next_version_unsafe()
    {
      // Get the next global version
      ++version;

      // Version was previously signed, with negative values representing
      // deletions. Maintain this restriction for compatibility with old code.
      if (version > std::numeric_limits<int64_t>::max())
      {
        LOG_FAIL_FMT("KV version too large - wrapping to 0");
        version = 0;
      }

      // Further transactions should read in the commit term
      term_of_last_version = term_of_next_version;

      return version;
    }

    TxID current_txid_unsafe()
    {
      // version_lock should be first acquired
      return {term_of_last_version, version};
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

    Store(const Store& that) = delete;

    std::shared_ptr<Consensus> get_consensus() override
    {
      // We need to use std::atomic_load<std::shared_ptr<T>>
      // after clang supports it.
      // https://en.cppreference.com/w/Template:cpp/compiler_support/20
      return std::atomic_load(&consensus);
    }

    void set_consensus(const std::shared_ptr<Consensus>& consensus_)
    {
      std::atomic_store(&consensus, consensus_);
    }

    std::shared_ptr<TxHistory> get_history() override
    {
      return history;
    }

    void set_history(const std::shared_ptr<TxHistory>& history_)
    {
      history = history_;
    }

    void set_encryptor(const EncryptorPtr& encryptor_)
    {
      encryptor = encryptor_;
    }

    EncryptorPtr get_encryptor() override
    {
      return encryptor;
    }

    void set_snapshotter(const SnapshotterPtr& snapshotter_)
    {
      snapshotter = snapshotter_;
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
     * @param map_ Map to add
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

    bool should_track_dependencies(const std::string& name) override
    {
      return name.compare(aft::Tables::AFT_REQUESTS) != 0;
    }

    std::unique_ptr<AbstractSnapshot> snapshot(
      Version v, bool unsafe_map = false) override
    {
      auto cv = compacted_version();
      if (v < cv)
      {
        throw std::logic_error(fmt::format(
          "Cannot snapshot at version {} which is earlier than last "
          "compacted version {} ",
          v,
          cv));
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
        std::unique_lock<ccf::pal::Mutex> mguard(maps_lock, std::defer_lock);

        if (!unsafe_map)
        {
          mguard.lock();

          for (auto& it : maps)
          {
            auto& [_, map] = it.second;
            map->lock();
          }
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

        if (!unsafe_map)
        {
          for (auto& it : maps)
          {
            auto& [_, map] = it.second;
            map->unlock();
          }
        }
      }

      return snapshot;
    }

    void lock_maps() override
    {
      maps_lock.lock();
      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->lock();
      }
    }

    void unlock_maps() override
    {
      for (auto& it : maps)
      {
        auto& [_, map] = it.second;
        map->unlock();
      }
      maps_lock.unlock();
    }

    std::vector<uint8_t> serialise_snapshot(
      std::unique_ptr<AbstractSnapshot> snapshot) override
    {
      auto e = get_encryptor();
      return snapshot->serialise(e);
    }

    ApplyResult deserialise_snapshot(
      const uint8_t* data,
      size_t size,
      kv::ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history = nullptr,
      bool public_only = false) override
    {
      auto e = get_encryptor();
      auto d = KvStoreDeserialiser(
        e,
        public_only ? kv::SecurityDomain::PUBLIC :
                      std::optional<kv::SecurityDomain>());

      kv::Term term;
      auto v_ = d.init(data, size, term, is_historical);
      if (!v_.has_value())
      {
        LOG_FAIL_FMT("Initialisation of deserialise object failed");
        return ApplyResult::FAIL;
      }
      auto v = v_.value();

      std::lock_guard<ccf::pal::Mutex> mguard(maps_lock);

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
            is_map_replicated(map_name),
            should_track_dependencies(map_name));
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
        changes.emplace_hint(
          changes_search,
          std::piecewise_construct,
          std::forward_as_tuple(map_name),
          std::forward_as_tuple(map, std::move(deserialised_snapshot_changes)));
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
      bool track_deletes_on_missing_keys = false;
      auto r = apply_changes(
        changes,
        [](bool) { return std::make_tuple(NoVersion, NoVersion); },
        hooks,
        new_maps,
        std::nullopt,
        false,
        track_deletes_on_missing_keys);
      if (!r.has_value())
      {
        LOG_FAIL_FMT("Failed to commit deserialised snapshot at version {}", v);
        return ApplyResult::FAIL;
      }

      {
        std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
        version = v;
        last_replicated = v;
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

      if (snapshotter)
      {
        auto c = get_consensus();
        bool generate_snapshot = c && c->is_primary();
        snapshotter->commit(v, generate_snapshot);
      }

      std::lock_guard<ccf::pal::Mutex> mguard(maps_lock);

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
        std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
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

    void rollback(const TxID& tx_id, Term term_of_next_version_) override
    {
      // This is called to roll the store back to the state it was in
      // at the specified version.
      // No transactions can be prepared or committed during rollback.

      if (snapshotter)
      {
        snapshotter->rollback(tx_id.version);
      }

      std::lock_guard<ccf::pal::Mutex> mguard(maps_lock);

      {
        std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
        if (tx_id.version < compacted)
        {
          throw std::logic_error(fmt::format(
            "Attempting rollback to {}, earlier than commit version {}",
            tx_id.version,
            compacted));
        }

        // The term should always be updated on rollback() when passed
        // regardless of whether version needs to be updated or not
        term_of_next_version = term_of_next_version_;
        term_of_last_version = tx_id.term;

        // History must be informed of the term_of_last_version change, even if
        // no actual rollback is required
        auto h = get_history();
        if (h)
        {
          h->rollback(tx_id, term_of_next_version);
        }

        if (tx_id.version >= version)
        {
          return;
        }

        version = tx_id.version;
        last_replicated = tx_id.version;
        unset_flag_unsafe(Flag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);
        unset_flag_unsafe(Flag::SNAPSHOT_AT_NEXT_SIGNATURE);
        rollback_count++;
        pending_txs.clear();
        auto e = get_encryptor();
        if (e)
        {
          e->rollback(tx_id.version);
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
        map->rollback(tx_id.version);
        if (map_creation_version > tx_id.version)
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

    void initialise_term(Term t) override
    {
      // Note: This should only be called once, when the store is first
      // initialised. term_of_next_version is later updated via rollback.
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      if (term_of_next_version != 0)
      {
        throw std::logic_error("term_of_next_version is already initialised");
      }

      term_of_next_version = t;
      auto h = get_history();
      if (h)
      {
        h->set_term(term_of_next_version);
      }
    }

    bool fill_maps(
      const std::vector<uint8_t>& data,
      bool public_only,
      kv::Version& v,
      kv::Term& view,
      OrderedChanges& changes,
      MapCollection& new_maps,
      ccf::ClaimsDigest& claims_digest,
      std::optional<crypto::Sha256Hash>& commit_evidence_digest,
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

      auto v_ = d.init(data.data(), data.size(), view, is_historical);
      if (!v_.has_value())
      {
        LOG_FAIL_FMT("Initialisation of deserialise object failed");
        return false;
      }
      v = v_.value();

      claims_digest = std::move(d.consume_claims_digest());
      LOG_TRACE_FMT(
        "Deserialised claim digest {} {}",
        claims_digest.value(),
        claims_digest.empty());

      commit_evidence_digest = std::move(d.consume_commit_evidence_digest());
      if (commit_evidence_digest.has_value())
        LOG_TRACE_FMT(
          "Deserialised commit evidence digest {}",
          commit_evidence_digest.value());

      // Throw away any local commits that have not propagated via the
      // consensus.
      rollback({term_of_last_version, v - 1}, term_of_next_version);

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
      std::lock_guard<ccf::pal::Mutex> mguard(maps_lock);

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
            is_map_replicated(map_name),
            should_track_dependencies(map_name));
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
        changes.emplace_hint(
          change_search,
          std::piecewise_construct,
          std::forward_as_tuple(map_name),
          std::forward_as_tuple(map, std::move(deserialised_changes)));
      }

      if (!d.end())
      {
        LOG_FAIL_FMT("Unexpected content in transaction at version {}", v);
        return false;
      }

      return true;
    }

    std::unique_ptr<kv::AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t>& data,
      ConsensusType consensus_type,
      bool public_only = false,
      const std::optional<TxID>& expected_txid = std::nullopt) override
    {
      if (consensus_type == ConsensusType::CFT)
      {
        auto exec = std::make_unique<CFTExecutionWrapper>(
          this, get_history(), std::move(data), public_only, expected_txid);
        return exec;
      }
      else
      {
        LOG_FAIL_FMT("Unsupported consensus type");
        return {};
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

    Version current_version() override
    {
      return version;
    }

    kv::TxID current_txid() override
    {
      // Must lock in case the version or read term is being incremented.
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      return current_txid_unsafe();
    }

    ccf::TxID get_txid() override
    {
      const auto kv_id = current_txid();
      return {kv_id.term, kv_id.version};
    }

    std::pair<TxID, Term> current_txid_and_commit_term() override
    {
      // Must lock in case the version or commit term is being incremented.
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      return {current_txid_unsafe(), term_of_next_version};
    }

    Version compacted_version() override
    {
      return compacted;
    }

    Term commit_view() override
    {
      // Must lock in case the commit_view is being incremented.
      return term_of_next_version;
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

      std::lock_guard<ccf::pal::Mutex> cguard(commit_lock);

      LOG_DEBUG_FMT(
        "Store::commit {}{}",
        txid.version,
        (globally_committable ? " globally_committable" : ""));

      BatchVector batch;
      Version previous_last_replicated = 0;
      Version next_last_replicated = 0;
      Version previous_rollback_count = 0;
      ccf::View replication_view = 0;

      {
        std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
        if (txid.term != term_of_next_version && get_consensus()->is_primary())
        {
          // This can happen when a transaction started before a view change,
          // but tries to commit after the view change is complete.
          LOG_DEBUG_FMT(
            "Want to commit for term {} but term is {}",
            txid.term,
            term_of_next_version);

          return CommitResult::FAIL_NO_REPLICATE;
        }

        if (globally_committable && txid.version > last_committable)
        {
          last_committable = txid.version;
        }

        pending_txs.insert(
          {txid.version,
           std::make_tuple(std::move(pending_tx), globally_committable)});

        LOG_TRACE_FMT("Inserting pending tx at {}", txid.version);

        auto h = get_history();
        auto c = get_consensus();

        for (Version offset = 1; true; ++offset)
        {
          auto search = pending_txs.find(last_replicated + offset);
          if (search == pending_txs.end())
          {
            LOG_TRACE_FMT(
              "Couldn't find {} = {} + {}, giving up on batch while committing "
              "{}.{}",
              last_replicated + offset,
              last_replicated,
              offset,
              txid.term,
              txid.version);
            break;
          }

          auto& [pending_tx_, committable_] = search->second;
          auto
            [success_, data_, claims_digest_, commit_evidence_digest_, hooks_] =
              pending_tx_->call();
          auto data_shared =
            std::make_shared<std::vector<uint8_t>>(std::move(data_));
          auto hooks_shared =
            std::make_shared<kv::ConsensusHookPtrs>(std::move(hooks_));

          // NB: this cannot happen currently. Regular Tx only make it here if
          // they did succeed, and signatures cannot conflict because they
          // execute in order with a read_version that's version - 1, so even
          // two contiguous signatures are fine
          if (success_ != CommitResult::SUCCESS)
          {
            LOG_DEBUG_FMT("Failed Tx commit {}", last_replicated + offset);
          }

          if (h)
          {
            h->append_entry(ccf::entry_leaf(
              *data_shared, commit_evidence_digest_, claims_digest_));
          }

          LOG_DEBUG_FMT(
            "Batching {} ({}) during commit of {}.{}",
            last_replicated + offset,
            data_shared->size(),
            txid.term,
            txid.version);

          batch.emplace_back(
            last_replicated + offset, data_shared, committable_, hooks_shared);
          pending_txs.erase(search);
        }

        if (batch.size() == 0)
        {
          return CommitResult::SUCCESS;
        }

        previous_rollback_count = rollback_count;
        previous_last_replicated = last_replicated;
        next_last_replicated = last_replicated + batch.size();

        replication_view = term_of_next_version;

        if (
          get_consensus()->type() == ConsensusType::BFT &&
          get_consensus()->is_backup())
        {
          last_replicated = next_last_replicated;
        }
      }

      if (c->replicate(batch, replication_view))
      {
        std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
        if (
          last_replicated == previous_last_replicated &&
          previous_rollback_count == rollback_count &&
          !(get_consensus()->type() == ConsensusType::BFT &&
            get_consensus()->is_backup()))
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

    bool must_force_ledger_chunk(Version version) override
    {
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      return must_force_ledger_chunk_unsafe(version);
    }

    bool must_force_ledger_chunk_unsafe(Version version) override
    {
      // Note that snapshotter->record_committable, and therefore this function,
      // assumes that `version` is a committable entry/signature.

      bool r = flag_enabled_unsafe(
                 AbstractStore::Flag::LEDGER_CHUNK_AT_NEXT_SIGNATURE) ||
        flag_enabled_unsafe(AbstractStore::Flag::SNAPSHOT_AT_NEXT_SIGNATURE);

      if (snapshotter)
      {
        r |= snapshotter->record_committable(version);
      }

      return r;
    }

    void lock() override
    {
      maps_lock.lock();
    }

    void unlock() override
    {
      maps_lock.unlock();
    }

    std::tuple<Version, Version> next_version(bool commit_new_map) override
    {
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      Version v = next_version_unsafe();

      auto previous_last_new_map = last_new_map;
      if (commit_new_map)
      {
        last_new_map = v;
      }

      return std::make_tuple(v, previous_last_new_map);
    }

    Version next_version() override
    {
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      return next_version_unsafe();
    }

    TxID next_txid() override
    {
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      next_version_unsafe();

      return {term_of_next_version, version};
    }

    size_t committable_gap() override
    {
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
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

      std::lock_guard<ccf::pal::Mutex> this_maps_guard(maps_lock);
      std::lock_guard<ccf::pal::Mutex> other_maps_guard(store.maps_lock);

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
              this,
              name,
              SecurityDomain::PRIVATE,
              is_map_replicated(name),
              should_track_dependencies(name)));
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

    ReadOnlyTx create_read_only_tx() override
    {
      return ReadOnlyTx(this);
    }

    TxDiff create_tx_diff() override
    {
      return TxDiff(this);
    }

    CommittableTx create_tx()
    {
      return CommittableTx(this);
    }

    std::unique_ptr<CommittableTx> create_tx_ptr()
    {
      return std::make_unique<CommittableTx>(this);
    }

    ReservedTx create_reserved_tx(const TxID& tx_id)
    {
      // version_lock should already been acquired in case term_of_last_version
      // is incremented.
      return ReservedTx(this, term_of_last_version, tx_id);
    }

    virtual void set_flag(Flag f) override
    {
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      set_flag_unsafe(f);
    }

    virtual void unset_flag(Flag f) override
    {
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      unset_flag_unsafe(f);
    }

    virtual bool flag_enabled(Flag f) override
    {
      std::lock_guard<ccf::pal::Mutex> vguard(version_lock);
      return flag_enabled_unsafe(f);
    }

    virtual void set_flag_unsafe(Flag f) override
    {
      this->flags |= static_cast<uint8_t>(f);
    }

    virtual void unset_flag_unsafe(Flag f) override
    {
      this->flags &= ~static_cast<uint8_t>(f);
    }

    virtual bool flag_enabled_unsafe(Flag f) const override
    {
      return (flags & static_cast<uint8_t>(f)) != 0;
    }
  };

  using StorePtr = std::shared_ptr<kv::Store>;
}
