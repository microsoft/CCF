// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_serialiser.h"
#include "kv_types.h"
#include "map.h"
#include "view_containers.h"

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
  class BaseTx : public AbstractViewContainer
  {
  protected:
    AbstractStore* store = nullptr;

    OrderedViews view_list;
    bool committed = false;
    bool success = false;
    Version read_version = NoVersion;
    Version version = NoVersion;
    Term term = 0;

    kv::TxHistory::RequestID req_id;

    std::map<std::string, std::shared_ptr<AbstractMap>> created_maps;

    template <typename MapView>
    std::tuple<MapView*> check_and_store_view(
      MapView* typed_view,
      const std::string& map_name,
      const std::shared_ptr<AbstractMap>& abstract_map)
    {
      if (typed_view == nullptr)
      {
        throw CompactedVersionConflict(fmt::format(
          "Unable to retrieve view over {} at {}", map_name, read_version));
      }

      auto abstract_view = dynamic_cast<AbstractTxView*>(typed_view);
      if (abstract_view == nullptr)
      {
        throw std::logic_error(
          fmt::format("View over map {} is not an AbstractTxView", map_name));
      }
      view_list[map_name] = {abstract_map,
                             std::unique_ptr<AbstractTxView>(abstract_view)};

      return std::make_tuple(typed_view);
    }

    template <class M>
    std::tuple<typename M::TxView*> get_view_tuple_by_name(
      const std::string& map_name)
    {
      if (store == nullptr)
      {
        CCF_ASSERT(
          false, "Cannot retrieve view: New form called on old-style Tx");
      }

      using MapView = typename M::TxView;

      // If the M is present, its AbstractTxView should be an M::TxView. This
      // invariant could be broken by set_view_list, which will produce an error
      // here
      auto search = view_list.find(map_name);
      if (search != view_list.end())
      {
        auto view = dynamic_cast<MapView*>(search->second.view.get());

        if (view == nullptr)
        {
          throw std::logic_error(
            fmt::format("View over map {} is not of expected type", map_name));
        }

        return std::make_tuple(view);
      }

      if (read_version == NoVersion)
      {
        // Grab opacity version that all Maps should be queried at.
        auto txid = store->current_txid();
        term = txid.term;
        read_version = txid.version;
      }

      MapView* typed_view = nullptr;

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
        LOG_DEBUG_FMT("Creating new map '{}'", map_name);

        abstract_map = new_map;
        typed_view = new_map->template create_view<MapView>(read_version);
      }
      else
      {
        auto* am = abstract_map.get();
        auto typed_map = dynamic_cast<M*>(am);
        if (typed_map == nullptr)
        {
          auto untyped_map = dynamic_cast<kv::untyped::Map*>(am);
          if (untyped_map == nullptr)
          {
            throw std::logic_error(
              fmt::format("Map {} has unexpected type", map_name));
          }
          else
          {
            typed_view =
              untyped_map->template create_view<MapView>(read_version);
          }
        }
        else
        {
          typed_view = typed_map->template create_view<MapView>(read_version);
        }
      }

      return check_and_store_view(typed_view, map_name, abstract_map);
    }

    template <class M, class... Ms>
    std::tuple<typename M::TxView*, typename Ms::TxView*...>
    get_view_tuple_by_types(M& m, Ms&... ms)
    {
      if constexpr (sizeof...(Ms) == 0)
      {
        return get_view_tuple_by_name<M>(m.get_name());
      }
      else
      {
        return std::tuple_cat(
          get_view_tuple_by_name<M>(m.get_name()),
          get_view_tuple_by_types(ms...));
      }
    }

    template <class M, class... Ms, class... Ts>
    std::tuple<typename M::TxView*, typename Ms::TxView*...>
    get_view_tuple_by_names(const std::string& map_name, const Ts&... names)
    {
      if constexpr (sizeof...(Ts) == 0)
      {
        return get_view_tuple_by_name<M>(map_name);
      }
      else
      {
        return std::tuple_cat(
          get_view_tuple_by_name<M>(map_name),
          get_view_tuple_by_names<Ms...>(names...));
      }
    }

  public:
    BaseTx(AbstractStore* _store) : store(_store) {}

    BaseTx(const BaseTx& that) = delete;

    void set_view_list(OrderedViews& view_list_, Term term_) override
    {
      // if view list is not empty then any coinciding keys will not be
      // overwritten
      view_list.merge(view_list_);
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

      if (view_list.empty())
      {
        committed = true;
        success = true;
        return CommitSuccess::OK;
      }

      auto store = view_list.begin()->second.map->get_store();

      // If this transaction may create maps, ensure that commit gets a
      // consistent view of the existing maps
      if (!created_maps.empty())
        this->store->lock();

      auto c = apply_views(
        view_list, [store]() { return store->next_version(); }, created_maps);

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
        version = c.value();

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
            MovePendingTx(std::move(data), std::move(req_id)),
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
        std::any_of(view_list.begin(), view_list.end(), [](const auto& it) {
          return it.second.view->has_changes();
        });

      if (!any_changes)
      {
        return {};
      }

      // Retrieve encryptor.
      auto map = view_list.begin()->second.map;
      auto e = map->get_store()->get_encryptor();

      KvStoreSerialiser replicated_serialiser(e, version);

      // Process in security domain order
      for (auto domain : {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
      {
        for (const auto& it : view_list)
        {
          const auto map = it.second.map;
          if (
            map->get_security_domain() == domain && map->is_replicated() &&
            it.second.view->has_changes())
          {
            map->serialise(
              it.second.view.get(), replicated_serialiser, include_reads);
          }
        }
      }

      // Return serialised Tx.
      return replicated_serialiser.get_raw_data();
    }

    // Used by frontend for reserved transactions
    BaseTx(Version reserved) :
      view_list(),
      committed(false),
      success(false),
      read_version(reserved - 1),
      version(reserved)
    {}

    // Used by frontend to commit reserved transactions
    PendingTxInfo commit_reserved()
    {
      if (committed)
        throw std::logic_error("Transaction already committed");

      if (view_list.empty())
        throw std::logic_error("Reserved transaction cannot be empty");

      auto c = apply_views(view_list, [this]() { return version; });
      success = c.has_value();

      if (!success)
        throw std::logic_error("Failed to commit reserved transaction");

      committed = true;
      return {CommitSuccess::OK, {0, 0, 0}, serialise()};
    }

    // Used to clear the Tx to its initial state, to retry after a conflict
    void reset()
    {
      view_list.clear();
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
      return std::get<0>(get_view_tuple_by_name<M>(m.get_name()));
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
      return std::get<0>(get_view_tuple_by_name<M>(map_name));
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
        get_view_tuple_by_name<M>(m.get_name()),
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
        get_view_tuple_by_name<M>(map_name),
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
      return std::get<0>(get_view_tuple_by_name<M>(m.get_name()));
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
      return std::get<0>(get_view_tuple_by_name<M>(map_name));
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
        get_view_tuple_by_name<M>(m.get_name()),
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
        get_view_tuple_by_name<M>(map_name),
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
      store = _store;
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

      if (view_list.empty())
        throw std::logic_error("Reserved transaction cannot be empty");

      auto c = apply_views(view_list, [this]() { return version; });
      success = c.has_value();

      if (!success)
        throw std::logic_error("Failed to commit reserved transaction");

      committed = true;
      return {CommitSuccess::OK, {0, 0, 0}, serialise()};
    }
  };
}
