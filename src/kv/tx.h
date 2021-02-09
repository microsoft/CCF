// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apply_changes.h"
#include "ds/ccf_assert.h"
#include "ds/ccf_deprecated.h"
#include "kv_serialiser.h"
#include "kv_types.h"
#include "map.h"

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

  // Manages a collection of MapHandles. Derived implementations should call
  // get_handle_by_name to retrieve handles over their desired maps.
  class BaseTx : public AbstractChangeContainer
  {
  protected:
    AbstractStore* store;

    OrderedChanges all_changes;

    // NB: This exists only to maintain the old API, where this Tx stores
    // MapHandles and returns raw pointers to them. It could be removed entirely
    // with a near-identical API if we return `shared_ptr`s, and assuming that
    // we don't actually care about returning exactly the same Handle instance
    // if `rw` is called multiple times
    using PossibleHandles = std::list<std::unique_ptr<AbstractMapHandle>>;
    std::map<std::string, PossibleHandles> all_handles;

    bool committed = false;
    bool success = false;
    Version read_version = NoVersion;
    Version version = NoVersion;
    Version max_conflict_version = NoVersion;
    Term term = 0;
    std::optional<crypto::Sha256Hash> root_at_read_version = std::nullopt;

    kv::TxHistory::RequestID req_id;

    std::map<std::string, std::shared_ptr<AbstractMap>> created_maps;

    template <typename THandle>
    THandle* get_or_insert_handle(
      untyped::ChangeSet& change_set, const std::string& name)
    {
      auto it = all_handles.find(name);
      if (it == all_handles.end())
      {
        PossibleHandles handles;
        auto typed_handle = new THandle(change_set);
        handles.emplace_back(std::unique_ptr<AbstractMapHandle>(typed_handle));
        all_handles[name] = std::move(handles);
        return typed_handle;
      }
      else
      {
        PossibleHandles& handles = it->second;
        for (auto& handle : handles)
        {
          auto typed_handle = dynamic_cast<THandle*>(handle.get());
          if (typed_handle != nullptr)
          {
            return typed_handle;
          }
        }
        auto typed_handle = new THandle(change_set);
        handles.emplace_back(std::unique_ptr<AbstractMapHandle>(typed_handle));
        return typed_handle;
      }
    }

    template <typename THandle>
    THandle* check_and_store_change_set(
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

      auto typed_handle = get_or_insert_handle<THandle>(*change_set, map_name);
      all_changes[map_name] = {abstract_map, std::move(change_set)};
      return typed_handle;
    }

    template <class THandle>
    THandle* get_handle_by_name(const std::string& map_name)
    {
      auto search = all_changes.find(map_name);
      if (search != all_changes.end())
      {
        auto handle =
          get_or_insert_handle<THandle>(*search->second.changeset, map_name);
        return handle;
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
            throw std::logic_error(
              "Created map without creating handle over it");
          }
        }

        // NB: The created maps are always untyped. Only the handles over them
        // are typed
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
      return check_and_store_change_set<THandle>(
        std::move(change_set), map_name, abstract_map);
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

    void set_read_version_and_term(Version v, Term t)
    {
      if (read_version == NoVersion)
      {
        read_version = v;
        term = t;
      }
      else
      {
        throw std::logic_error("Read version already set");
      }
    }

    void set_root_at_read_version(const crypto::Sha256Hash& r)
    {
      root_at_read_version = r;
    }

    std::optional<crypto::Sha256Hash> get_root_at_read_version()
    {
      return root_at_read_version;
    }

    /** Commit transaction
     *
     * A transaction can either succeed and replicate
     * (`kv::CommitResult::SUCCESS`), fail because of a conflict with other
     * transactions
     * (`kv::CommitResult::FAIL_CONFLICT`), or succeed locally, but fail to
     * replicate (`kv::CommitResult::FAIL_NO_REPLICATE`).
     *
     * Transactions that fail are rolled back, no matter the reason.
     *
     * @return transaction outcome
     */
    CommitResult commit()
    {
      if (committed)
        throw std::logic_error("Transaction already committed");

      if (all_changes.empty())
      {
        committed = true;
        success = true;
        return CommitResult::SUCCESS;
      }

      auto store = all_changes.begin()->second.map->get_store();

      // If this transaction creates any maps, ensure that commit gets a
      // consistent snapshot of the existing maps
      if (!created_maps.empty())
        this->store->lock();

      kv::ConsensusHookPtrs hooks;

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
        // Conflicting handles (and contained writes) and all version tracking
        // are discarded. They must be reconstructed at updated, non-conflicting
        // versions
        reset();

        LOG_TRACE_FMT("Could not commit transaction due to conflict");
        return CommitResult::FAIL_CONFLICT;
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
            return CommitResult::SUCCESS;
          }

          return store->commit(
            {term, version},
            std::make_unique<MovePendingTx>(
              std::move(data), std::move(req_id), std::move(hooks)),
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

      KvStoreSerialiser replicated_serialiser(
        e, {term, version}, max_conflict_version);

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
      all_handles.clear();
      created_maps.clear();
      committed = false;
      success = false;
      read_version = NoVersion;
      version = NoVersion;
      term = 0;
      root_at_read_version = std::nullopt;
    }
  };

  /** Used to create read-only handles for accessing a Map.
   *
   * Acquiring a handle will create the map in the KV if it does not yet exist.
   * The returned handles can view state written by previous transactions, and
   * any additional modifications made in this transaction.
   */
  class ReadOnlyTx : public BaseTx
  {
  public:
    using BaseTx::BaseTx;

    /** Get a read-only handle from a map instance.
     *
     * @param m Map instance
     */
    template <class M>
    typename M::ReadOnlyHandle* ro(M& m)
    {
      // NB: Always creates a (writeable) MapHandle, which is cast to
      // ReadOnlyHandle on return. This is so that other calls (before or
      // after) can retrieve writeable handles over the same map.
      return get_handle_by_name<typename M::Handle>(m.get_name());
    }

    /** Get a read-only handle by map name. Map type must be specified
     * as explicit template parameter.
     *
     * @param map_name Name of map
     */
    template <class M>
    typename M::ReadOnlyHandle* ro(const std::string& map_name)
    {
      return get_handle_by_name<typename M::Handle>(map_name);
    }

    template <class M>
    CCF_DEPRECATED("Replace with ro")
    typename M::ReadOnlyHandle* get_read_only_view(M& m)
    {
      return ro<M>(m);
    }

    template <class M>
    CCF_DEPRECATED("Replace with ro")
    typename M::ReadOnlyHandle* get_read_only_view(const std::string& map_name)
    {
      return ro<M>(map_name);
    }
  };

  /** Used to create writeable handles for accessing a Map.
   *
   * Acquiring a handle will create the map in the KV if it does not yet exist.
   * Any writes made by the returned handles will be visible to all other
   * handles created by this transaction. They will only be visible to other
   * transactions after this transaction has completed and been applied. For
   * type-safety, prefer restricted handles returned by @c ro or @c wo where
   * possible, rather than the general @c rw.
   *
   * @see kv::ReadOnlyTx
   */
  class Tx : public ReadOnlyTx
  {
  public:
    using ReadOnlyTx::ReadOnlyTx;

    /** Get a read-write handle from a map instance.
     *
     * This handle can be used for both reads and writes.
     *
     * @param m Map instance
     */
    template <class M>
    typename M::Handle* rw(M& m)
    {
      return get_handle_by_name<typename M::Handle>(m.get_name());
    }

    /** Get a read-write handle by map name. Map type must be specified
     * as explicit template parameter.
     *
     * @param map_name Name of map
     */
    template <class M>
    typename M::Handle* rw(const std::string& map_name)
    {
      return get_handle_by_name<typename M::Handle>(map_name);
    }

    template <class M>
    CCF_DEPRECATED("Replace with rw")
    typename M::ReadOnlyHandle* get_view(M& m)
    {
      return rw<M>(m);
    }

    template <class M>
    CCF_DEPRECATED("Replace with rw")
    typename M::ReadOnlyHandle* get_view(const std::string& map_name)
    {
      return rw<M>(map_name);
    }

    /** Get a write-only handle from a map instance.
     *
     * @param m Map instance
     */
    template <class M>
    typename M::WriteOnlyHandle* wo(M& m)
    {
      // As with ro, this returns a full-featured Handle
      // which is cast to only show its writeable facet.
      return get_handle_by_name<typename M::Handle>(m.get_name());
    }

    /** Get a read-write handle by map name. Map type must be specified
     * as explicit template parameter.
     *
     * @param map_name Name of map
     */
    template <class M>
    typename M::WriteOnlyHandle* wo(const std::string& map_name)
    {
      return get_handle_by_name<typename M::Handle>(map_name);
    }
  };

  // Used by frontend for reserved transactions. These are constructed with a
  // pre-reserved Version, and _must succeed_ to fulfil this version. Otherwise
  // they create a hole in the transaction order, and no future transactions can
  // complete.
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

      std::vector<ConsensusHookPtr> hooks;
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
      return {CommitResult::SUCCESS, {0, 0}, serialise(), std::move(hooks)};
    }
  };
}
