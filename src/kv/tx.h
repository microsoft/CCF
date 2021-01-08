// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"
#include "kv_serialiser.h"
#include "kv_types.h"
#include "map.h"
#include "view_containers.h"

#include <list>

namespace kv
{
  class CompactedVersionConflict
  {
  private:
    std::string msg;

  public:
    CompactedVersionConflict(const std::string& s) : msg(s) {}

    char const* what() const
    {
      return msg.c_str();
    }
  };

  // Manages a collection of TxViews. Derived implementations call get_tuple to
  // retrieve views over target maps.
  class BaseTx : public AbstractChangeContainer
  {
  protected:
    AbstractStore* store;

    OrderedChanges all_changes;

    // NB: This exists only to maintain the old API, where this Tx stores
    // TxViews and returns raw pointers to them. It could be removed entirely
    // with a near-identical API if we return `shared_ptr`s, and assuming that
    // we don't actually care about returning the same View instance if
    // `get_view` is called multiple times
    using PossibleViews = std::list<std::unique_ptr<AbstractTxView>>;
    std::map<std::string, PossibleViews> all_views;

    bool committed = false;
    bool success = false;
    Version read_version = NoVersion;
    Version version = NoVersion;
    Version max_conflict_version = NoVersion;
    Term term = 0;

    kv::TxHistory::RequestID req_id;

    std::map<std::string, std::shared_ptr<AbstractMap>> created_maps;

    template <typename MapView>
    MapView* get_or_insert_view(
      untyped::ChangeSet& change_set, const std::string& name)
    {
      auto it = all_views.find(name);
      if (it == all_views.end())
      {
        PossibleViews views;
        auto typed_view = new MapView(change_set);
        views.emplace_back(std::unique_ptr<AbstractTxView>(typed_view));
        all_views[name] = std::move(views);
        return typed_view;
      }
      else
      {
        PossibleViews& views = it->second;
        for (auto& view : views)
        {
          auto typed_view = dynamic_cast<MapView*>(view.get());
          if (typed_view != nullptr)
          {
            return typed_view;
          }
        }
        auto typed_view = new MapView(change_set);
        views.emplace_back(std::unique_ptr<AbstractTxView>(typed_view));
        return typed_view;
      }
    }

    template <typename MapView>
    std::tuple<MapView*> check_and_store_change_set(
      std::unique_ptr<untyped::ChangeSet>&& change_set,
      const std::string& map_name,
      const std::shared_ptr<AbstractMap>& abstract_map)
    {
      if (change_set == nullptr)
      {
        throw CompactedVersionConflict(fmt::format(
          "Unable to retrieve state over map {} at {}",
          map_name,
          read_version));
      }

      auto typed_view = get_or_insert_view<MapView>(*change_set, map_name);
      all_changes[map_name] = {abstract_map, std::move(change_set)};
      return std::make_tuple(typed_view);
    }

    template <class MapView>
    std::tuple<MapView*> get_view_tuple_by_name(const std::string& map_name)
    {
      auto search = all_changes.find(map_name);
      if (search != all_changes.end())
      {
        auto view =
          get_or_insert_view<MapView>(*search->second.changeset, map_name);
        return std::make_tuple(view);
      }

      if (read_version == NoVersion)
      {
        // Grab opacity version that all Maps should be queried at.
        auto txid = store->current_txid();
        term = txid.term;
        read_version = txid.version;
      }

      auto abstract_map = store->get_map(read_version, map_name);
      if (abstract_map == nullptr)
      {
        // Store doesn't know this map yet - create it dynamically
        {
          const auto map_it = created_maps.find(map_name);
          if (map_it != created_maps.end())
          {
            throw std::logic_error("Created map without creating view over it");
          }
        }

        // NB: The created maps are always untyped. Only the views over them are
        // typed
        auto new_map = std::make_shared<kv::untyped::Map>(
          store,
          map_name,
          kv::get_security_domain(map_name),
          store->is_map_replicated(map_name));
        created_maps[map_name] = new_map;

        abstract_map = new_map;
      }

      auto untyped_map =
        std::dynamic_pointer_cast<kv::untyped::Map>(abstract_map);
      if (untyped_map == nullptr)
      {
        throw std::logic_error(
          fmt::format("Map {} has unexpected type", map_name));
      }

      auto change_set = untyped_map->create_change_set(read_version);
      return check_and_store_change_set<MapView>(
        std::move(change_set), map_name, abstract_map);
    }

    template <class M, class... Ms>
    std::tuple<typename M::TxView*, typename Ms::TxView*...>
    get_view_tuple_by_types(M& m, Ms&... ms)
    {
      if constexpr (sizeof...(Ms) == 0)
      {
        return get_view_tuple_by_name<typename M::TxView>(m.get_name());
      }
      else
      {
        return std::tuple_cat(
          get_view_tuple_by_name<typename M::TxView>(m.get_name()),
          get_view_tuple_by_types(ms...));
      }
    }

    template <class M, class... Ms, class... Ts>
    std::tuple<typename M::TxView*, typename Ms::TxView*...>
    get_view_tuple_by_names(const std::string& map_name, const Ts&... names)
    {
      if constexpr (sizeof...(Ts) == 0)
      {
        return get_view_tuple_by_name<typename M::TxView>(map_name);
      }
      else
      {
        return std::tuple_cat(
          get_view_tuple_by_name<typename M::TxView>(map_name),
          get_view_tuple_by_names<Ms...>(names...));
      }
    }

  public:
    BaseTx(AbstractStore* _store, bool known_null = false) : store(_store)
    {
      // For testing purposes, caller may opt-in to creation of an unsafe Tx by
      // passing (nullptr, true). Many operations on this Tx, including
      // commit(), will try to dereference this pointer, so the caller must not
      // call these.
      if (!known_null)
      {
        CCF_ASSERT(
          store != nullptr,
          "Transactions must be created with reference to real Store");
      }
    }

    BaseTx(const BaseTx& that) = delete;

    void set_change_list(OrderedChanges&& change_list_, Term term_) override
    {
      // if all_changes is not empty then any coinciding keys will not be
      // overwritten
      all_changes.merge(change_list_);
      term = term_;
    }

    void set_req_id(const kv::TxHistory::RequestID& req_id_)
    {
      req_id = req_id_;
    }

    const kv::TxHistory::RequestID& get_req_id()
    {
      return req_id;
    }

    /** Version for the transaction set
     *
     * @return Committed version, or `kv::NoVersion` otherwise
     */
    Version get_version()
    {
      return version;
    }

    Version get_read_version()
    {
      return read_version;
    }

    Version get_term()
    {
      return term;
    }

    /** Commit transaction
     *
     * A transaction can either succeed and replicate (`kv::CommitSuccess::OK`),
     * fail because of a conflict with other transactions
     * (`kv::CommitSuccess::CONFLICT`), or succeed locally, but fail to
     * replicate (`kv::CommitSuccess::NO_REPLICATE`).
     *
     * Transactions that fail are rolled back, no matter the reason.
     *
     * @return transaction outcome
     */
    CommitSuccess commit()
    {
      if (committed)
        throw std::logic_error("Transaction already committed");

      if (all_changes.empty())
      {
        committed = true;
        success = true;
        return CommitSuccess::OK;
      }

      auto store = all_changes.begin()->second.map->get_store();

      // If this transaction may create maps, ensure that commit gets a
      // consistent view of the existing maps
      if (!created_maps.empty())
        this->store->lock();

      std::vector<std::shared_ptr<ConsensusHook>> hooks;

      auto c = apply_changes(
        all_changes,
        [store]() { return store->next_version(); },
        hooks,
        created_maps);

      if (!created_maps.empty())
        this->store->unlock();

      success = c.has_value();

      if (!success)
      {
        // Conflicting views (and contained writes) and all version tracking are
        // discarded. They must be reconstructed at updated, non-conflicting
        // versions
        reset();

        LOG_TRACE_FMT("Could not commit transaction due to conflict");
        return CommitSuccess::CONFLICT;
      }
      else
      {
        committed = true;
        std::tie(version, max_conflict_version) = c.value();

        // From here, we have received a unique commit version and made
        // modifications to our local kv. If we fail in any way, we cannot
        // recover.
        try
        {
          auto data = serialise();

          if (data.empty())
          {
            auto h = store->get_history();
            if (h != nullptr)
            {
              // This tx does not have a write set, so this is a read only tx
              // because of this we are returning NoVersion
              h->add_result(req_id, NoVersion);
            }
            return CommitSuccess::OK;
          }

          return store->commit(
            {term, version},
            MovePendingTx(std::move(data), std::move(req_id), std::move(hooks)),
            false);
        }
        catch (const std::exception& e)
        {
          committed = false;

          LOG_FAIL_FMT("Error during serialisation");
          LOG_DEBUG_FMT("Error during serialisation: {}", e.what());

          // Discard original exception type, throw as now fatal
          // KvSerialiserException
          throw KvSerialiserException(e.what());
        }
      }
    }

    /** Commit version if committed
     *
     * @return Commit version
     */
    Version commit_version()
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      return version;
    }

    /** Commit term if committed
     *
     * @return Commit term
     */
    Version commit_term()
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      return term;
    }

    std::vector<uint8_t> serialise(bool include_reads = false)
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      // If no transactions made changes, return a zero length vector.
      const bool any_changes =
        std::any_of(all_changes.begin(), all_changes.end(), [](const auto& it) {
          return it.second.changeset->has_writes();
        });

      if (!any_changes)
      {
        return {};
      }

      // Retrieve encryptor.
      auto map = all_changes.begin()->second.map;
      auto e = map->get_store()->get_encryptor();

      if (max_conflict_version == NoVersion)
      {
        max_conflict_version = version - 1;
      }

      KvStoreSerialiser replicated_serialiser(e, version, max_conflict_version);

      // Process in security domain order
      for (auto domain : {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
      {
        for (const auto& it : all_changes)
        {
          const auto& map = it.second.map;
          const auto& changeset = it.second.changeset;
          if (
            map->get_security_domain() == domain && map->is_replicated() &&
            changeset->has_writes())
          {
            map->serialise_changes(
              changeset.get(), replicated_serialiser, include_reads);
          }
        }
      }

      // Return serialised Tx.
      return replicated_serialiser.get_raw_data();
    }

    // Used by frontend for reserved transactions
    BaseTx(Version reserved) :
      committed(false),
      success(false),
      read_version(reserved - 1),
      version(reserved)
    {}

    // Used to clear the Tx to its initial state, to retry after a conflict
    void reset()
    {
      all_changes.clear();
      all_views.clear();
      created_maps.clear();
      committed = false;
      success = false;
      read_version = NoVersion;
      version = NoVersion;
      term = 0;
    }
  };

  class ReadOnlyTx : public BaseTx
  {
  public:
    using BaseTx::BaseTx;

    /** Get a read-only transaction view on a map.
     *
     * This adds the map to the transaction set if it is not yet present.
     *
     * @param m Map
     */
    template <class M>
    typename M::ReadOnlyTxView* get_read_only_view(M& m)
    {
      // NB: Always creates a (writeable) TxView, which is cast to
      // ReadOnlyTxView on return. This is so that other calls (before or after)
      // can retrieve writeable views over the same map.
      return std::get<0>(
        get_view_tuple_by_name<typename M::TxView>(m.get_name()));
    }

    /** Get a read-only transaction view on a map by name.
     *
     * This adds the map to the transaction set if it is not yet present, and
     * creates the map if it does not yet exist.
     *
     * @param map_name Name of map
     */
    template <class M>
    typename M::ReadOnlyTxView* get_read_only_view(const std::string& map_name)
    {
      return std::get<0>(get_view_tuple_by_name<typename M::TxView>(map_name));
    }

    /** Get read-only transaction views over multiple maps.
     *
     * @param m Map
     * @param ms Map
     */
    template <class M, class... Ms>
    std::tuple<typename M::ReadOnlyTxView*, typename Ms::ReadOnlyTxView*...>
    get_read_only_view(M& m, Ms&... ms)
    {
      return std::tuple_cat(
        get_view_tuple_by_name<typename M::TxView>(m.get_name()),
        get_view_tuple_by_types(ms...));
    }

    /** Get read-only transaction views over multiple maps by name. This will
     * create the maps if they do not exist.
     *
     * @param map_name Name of first map to retrieve
     * @param names Names of additional maps
     */
    template <class M, class... Ms, class... Ts>
    std::tuple<typename M::TxView*, typename Ms::TxView*...> get_read_only_view(
      const std::string& map_name, const Ts&... names)
    {
      return std::tuple_cat(
        get_view_tuple_by_name<typename M::TxView>(map_name),
        get_view_tuple_by_names<Ms...>(names...));
    }
  };

  class Tx : public ReadOnlyTx
  {
  public:
    using ReadOnlyTx::ReadOnlyTx;

    /** Get a transaction view on a map.
     *
     * This adds the map to the transaction set if it is not yet present.
     *
     * @param m Map
     */
    template <class M>
    typename M::TxView* get_view(M& m)
    {
      return std::get<0>(
        get_view_tuple_by_name<typename M::TxView>(m.get_name()));
    }

    /** Get a transaction view on a map by name
     *
     * This adds the map to the transaction set if it is not yet present, and
     * creates the map if it does not yet exist.
     *
     * @param map_name Name of map
     */
    template <class M>
    typename M::TxView* get_view(const std::string& map_name)
    {
      return std::get<0>(get_view_tuple_by_name<typename M::TxView>(map_name));
    }

    /** Get transaction views over multiple maps.
     *
     * @param m Map
     * @param ms Map
     */
    template <class M, class... Ms>
    std::tuple<typename M::TxView*, typename Ms::TxView*...> get_view(
      M& m, Ms&... ms)
    {
      return std::tuple_cat(
        get_view_tuple_by_name<typename M::TxView>(m.get_name()),
        get_view_tuple_by_types(ms...));
    }

    /** Get transaction views over multiple maps by name. This will create the
     * maps if they do not exist.
     *
     * @param map_name Name of first map to retrieve
     * @param names Names of additional maps
     */
    template <class M, class... Ms, class... Ts>
    std::tuple<typename M::TxView*, typename Ms::TxView*...> get_view(
      const std::string& map_name, const Ts&... names)
    {
      return std::tuple_cat(
        get_view_tuple_by_name<typename M::TxView>(map_name),
        get_view_tuple_by_names<Ms...>(names...));
    }
  };

  // Used by frontend for reserved transactions. These are constructed with a
  // pre-reserved Version, and _must succeed_ to fulfil this version, else
  // creating a hole in the history
  class ReservedTx : public Tx
  {
  public:
    ReservedTx(AbstractStore* _store, Version reserved) : Tx(_store)
    {
      committed = false;
      success = false;
      read_version = reserved - 1;
      version = reserved;
    }

    // Used by frontend to commit reserved transactions
    PendingTxInfo commit_reserved()
    {
      if (committed)
        throw std::logic_error("Transaction already committed");

      if (all_changes.empty())
        throw std::logic_error("Reserved transaction cannot be empty");

      std::vector<std::shared_ptr<ConsensusHook>> hooks;
      auto c = apply_changes(
        all_changes,
        [this]() { return version; },
        hooks,
        created_maps,
        version);
      success = c.has_value();

      if (!success)
        throw std::logic_error("Failed to commit reserved transaction");

      committed = true;
      return {CommitSuccess::OK, {0, 0}, serialise(), std::move(hooks)};
    }
  };
}
