// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_assert.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/tx_id.h"

#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace kv
{
  class AbstractHandle;
  class AbstractMap;
  class AbstractStore;

  namespace untyped
  {
    struct ChangeSet;
  }

  struct MapChanges
  {
    MapChanges(
      const std::shared_ptr<AbstractMap>& m,
      std::unique_ptr<untyped::ChangeSet>&& cs);
    ~MapChanges();

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
    struct PrivateImpl;
    std::unique_ptr<PrivateImpl> pimpl;

    OrderedChanges all_changes;

    std::optional<crypto::Sha256Hash> root_at_read_version = std::nullopt;

    void retain_change_set(
      const std::string& map_name,
      std::unique_ptr<untyped::ChangeSet>&& change_set,
      const std::shared_ptr<AbstractMap>& abstract_map);
    void retain_handle(
      const std::string& map_name, std::unique_ptr<AbstractHandle>&& handle);

    MapChanges get_map_and_change_set_by_name(
      const std::string& map_name, bool track_deletes_on_missing_keys);

    std::list<AbstractHandle*> get_possible_handles(
      const std::string& map_name);

    void compacted_version_conflict(const std::string& map_name);

    template <class THandle>
    THandle* get_handle_by_name(
      const std::string& map_name, bool track_deletes_on_missing_keys)
    {
      auto possible_handles = get_possible_handles(map_name);
      for (auto handle : possible_handles)
      {
        auto typed_handle = dynamic_cast<THandle*>(handle);
        if (typed_handle != nullptr)
        {
          return typed_handle;
        }
      }

      auto it = all_changes.find(map_name);
      if (it != all_changes.end())
      {
        auto& [abstract_map, change_set] = it->second;

        auto typed_handle = new THandle(*change_set, map_name);
        std::unique_ptr<AbstractHandle> abstract_handle(typed_handle);
        retain_handle(map_name, std::move(abstract_handle));
        return typed_handle;
      }
      else
      {
        auto [abstract_map, change_set] = get_map_and_change_set_by_name(
          map_name, track_deletes_on_missing_keys);

        if (change_set == nullptr)
        {
          compacted_version_conflict(map_name);
        }

        auto typed_handle = new THandle(*change_set, map_name);
        std::unique_ptr<AbstractHandle> abstract_handle(typed_handle);
        retain_handle(map_name, std::move(abstract_handle));
        retain_change_set(map_name, std::move(change_set), abstract_map);
        return typed_handle;
      }
    }

  public:
    BaseTx(AbstractStore* _store);

    // To avoid accidental copies and promote use of pass-by-reference, this is
    // non-copyable
    BaseTx(const BaseTx& that) = delete;

    // To support reset/reconstruction, this is move-assignable.
    BaseTx& operator=(BaseTx&& other) = default;

    virtual ~BaseTx();

    std::optional<crypto::Sha256Hash> get_root_at_read_version()
    {
      return root_at_read_version;
    }
  };

  class TxDiff : public BaseTx
  {
  public:
    using BaseTx::BaseTx;

    template <class M>
    typename M::Diff* diff(M& m)
    {
      return get_handle_by_name<typename M::Diff>(m.get_name(), true);
    }

    /** Get a diff by map name. Map type must be specified
     * as explicit template parameter.
     *
     * @param map_name Name of map
     */
    template <class M>
    typename M::Diff* diff(const std::string& map_name)
    {
      return get_handle_by_name<typename M::Diff>(map_name, true);
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
      return get_handle_by_name<typename M::Handle>(m.get_name(), false);
    }

    /** Get a read-only handle by map name. Map type must be specified
     * as explicit template parameter.
     *
     * @param map_name Name of map
     */
    template <class M>
    typename M::ReadOnlyHandle* ro(const std::string& map_name)
    {
      return get_handle_by_name<typename M::Handle>(map_name, false);
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
      return get_handle_by_name<typename M::Handle>(m.get_name(), false);
    }

    /** Get a read-write handle by map name. Map type must be specified
     * as explicit template parameter.
     *
     * @param map_name Name of map
     */
    template <class M>
    typename M::Handle* rw(const std::string& map_name)
    {
      return get_handle_by_name<typename M::Handle>(map_name, false);
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
      return get_handle_by_name<typename M::Handle>(m.get_name(), false);
    }

    /** Get a write-only handle by map name. Map type must be specified
     * as explicit template parameter.
     *
     * @param map_name Name of map
     */
    template <class M>
    typename M::WriteOnlyHandle* wo(const std::string& map_name)
    {
      return get_handle_by_name<typename M::Handle>(map_name, false);
    }
  };
}
