// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"
#include "crypto/hash.h"
#include "ds/ccf_assert.h"
#include "kv/kv_types.h"
#include "kv/untyped_map.h"

#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>

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

  struct MapChanges
  {
    // Shared ownership over source map
    std::shared_ptr<AbstractMap> map;

    // Owning pointer of ChangeSet over that map
    std::unique_ptr<untyped::ChangeSet> changeset;
  };

  // When a collection of Maps are locked, the locks must be acquired in a
  // stable order to avoid deadlocks. This ordered map will claim in name-order
  using OrderedChanges = std::map<std::string, MapChanges>;

  // Manages a collection of MapHandles. Derived implementations should call
  // get_handle_by_name to retrieve handles over their desired maps.
  class BaseTx
  {
  protected:
    AbstractStore* store;

    OrderedChanges all_changes;

    // NB: This exists only to maintain the old API, where this Tx stores
    // MapHandles and returns raw pointers to them. It could be removed entirely
    // with a near-identical API if we return `shared_ptr`s, and assuming that
    // we don't actually care about returning exactly the same Handle instance
    // if `rw` is called multiple times
    using PossibleHandles = std::list<std::unique_ptr<AbstractHandle>>;
    std::map<std::string, PossibleHandles> all_handles;

    // In most places we use NoVersion to indicate an invalid version. In this
    // case, NoVersion is a valid value - it is the version that the first
    // transaction in the service will read from, before anything has been
    // applied to the KV. So we need an additional special value to distinguish
    // "haven't yet fetched a read_version" from "have fetched a read_version,
    // and it is NoVersion", and we get that by wrapping this in a
    // std::optional with nullopt representing "not yet fetched".
    std::optional<Version> read_version = std::nullopt;
    ccf::View view = ccf::VIEW_UNKNOWN;
    // std::optional<ccf::View> replicated_view;

    std::map<std::string, std::shared_ptr<AbstractMap>> created_maps;

    std::optional<crypto::Sha256Hash> root_at_read_version = std::nullopt;

    template <typename THandle>
    THandle* get_or_insert_handle(
      untyped::ChangeSet& change_set, const std::string& name)
    {
      auto it = all_handles.find(name);
      if (it == all_handles.end())
      {
        PossibleHandles handles;
        auto typed_handle = new THandle(change_set, name);
        handles.emplace_back(std::unique_ptr<AbstractHandle>(typed_handle));
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
        auto typed_handle = new THandle(change_set, name);
        handles.emplace_back(std::unique_ptr<AbstractHandle>(typed_handle));
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
          read_version.value()));
      }

      auto typed_handle = get_or_insert_handle<THandle>(*change_set, map_name);
      all_changes[map_name] = {abstract_map, std::move(change_set)};
      return typed_handle;
    }

    auto get_map_and_change_set_by_name(const std::string& map_name)
    {
      if (!read_version.has_value())
      {
        // Grab opacity version that all Maps should be queried at.
        auto txid = store->current_txid();
        view = txid.term;
        read_version = txid.version;
      }

      auto abstract_map = store->get_map(read_version.value(), map_name);
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
          store->is_map_replicated(map_name),
          store->should_track_dependencies(map_name));
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

      return std::make_pair(
        abstract_map, untyped_map->create_change_set(read_version.value()));
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

      auto [abstract_map, change_set] =
        get_map_and_change_set_by_name(map_name);
      return check_and_store_change_set<THandle>(
        std::move(change_set), map_name, abstract_map);
    }

  public:
    BaseTx(AbstractStore* _store) : store(_store) {}

    // To avoid accidental copies and promote use of pass-by-reference, this is
    // non-copyable
    BaseTx(const BaseTx& that) = delete;

    // To support reset/reconstruction, it is move-assignable
    BaseTx& operator=(BaseTx&&) = default;

    std::optional<crypto::Sha256Hash> get_root_at_read_version()
    {
      return root_at_read_version;
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
}
