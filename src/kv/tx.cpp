// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/tx.h"

#include "ccf/ccf_assert.h"
#include "kv/compacted_version_conflict.h"
#include "kv/kv_types.h"
#include "kv/tx_pimpl.h"
#include "kv/untyped_map.h"

namespace kv
{
  MapChanges::MapChanges(
    const std::shared_ptr<AbstractMap>& m,
    std::unique_ptr<untyped::ChangeSet>&& cs) :
    map(m),
    changeset(std::move(cs))
  {}

  // Use default destructor, but instantiate here where untyped::ChangeSet is
  // not incomplete
  MapChanges::~MapChanges() = default;

  void BaseTx::retain_change_set(
    const std::string& map_name,
    std::unique_ptr<untyped::ChangeSet>&& change_set,
    const std::shared_ptr<AbstractMap>& abstract_map)
  {
    const auto it = all_changes.find(map_name);
    if (it != all_changes.end())
    {
      throw std::logic_error(
        fmt::format("Re-creating change set for map {}", map_name));
    }
    all_changes.emplace_hint(
      it,
      std::piecewise_construct,
      std::forward_as_tuple(map_name),
      std::forward_as_tuple(abstract_map, std::move(change_set)));
  }

  void BaseTx::retain_handle(
    const std::string& map_name, std::unique_ptr<AbstractHandle>&& handle)
  {
    pimpl->all_handles[map_name].emplace_back(std::move(handle));
  }

  MapChanges BaseTx::get_map_and_change_set_by_name(
    const std::string& map_name, bool track_deletes_on_missing_keys)
  {
    if (!pimpl->read_txid.has_value())
    {
      // Grab opacity version that all Maps should be queried at.
      // Note: It is by design that we delay acquiring a read version to now
      // rather than earlier, at Tx construction. This is to minimise the
      // window during which concurrent transactions can write to the same map
      // and cause this transaction to conflict on commit.
      std::tie(pimpl->read_txid, pimpl->commit_view) =
        pimpl->store->current_txid_and_commit_term();
    }

    auto abstract_map =
      pimpl->store->get_map(pimpl->read_txid->version, map_name);
    if (abstract_map == nullptr)
    {
      // Store doesn't know this map yet - create it dynamically
      {
        const auto map_it = pimpl->created_maps.find(map_name);
        if (map_it != pimpl->created_maps.end())
        {
          throw std::logic_error("Created map without creating handle over it");
        }
      }

      // NB: The created maps are always untyped. Only the handles over them
      // are typed
      auto new_map = std::make_shared<kv::untyped::Map>(
        pimpl->store,
        map_name,
        kv::get_security_domain(map_name),
        pimpl->store->is_map_replicated(map_name),
        pimpl->store->should_track_dependencies(map_name));
      pimpl->created_maps[map_name] = new_map;

      abstract_map = new_map;
    }

    auto untyped_map =
      std::dynamic_pointer_cast<kv::untyped::Map>(abstract_map);
    if (untyped_map == nullptr)
    {
      throw std::logic_error(
        fmt::format("Map {} has unexpected type", map_name));
    }

    return {
      abstract_map,
      untyped_map->create_change_set(
        pimpl->read_txid->version, track_deletes_on_missing_keys)};
  }

  std::list<AbstractHandle*> BaseTx::get_possible_handles(
    const std::string& map_name)
  {
    std::list<AbstractHandle*> handles;
    auto it = pimpl->all_handles.find(map_name);
    if (it != pimpl->all_handles.end())
    {
      for (auto& handle : it->second)
      {
        handles.push_back(handle.get());
      }
    }
    return handles;
  }

  void BaseTx::compacted_version_conflict(const std::string& map_name)
  {
    CCF_ASSERT_FMT(
      pimpl->read_txid.has_value(), "read_txid should have already been set");
    throw CompactedVersionConflict(fmt::format(
      "Unable to retrieve state over map {} at {}",
      map_name,
      pimpl->read_txid->version));
  }

  BaseTx::BaseTx(AbstractStore* store_)
  {
    pimpl = std::make_unique<PrivateImpl>();
    pimpl->store = store_;
  }

  // Use default destructor, but instantiate here where PrivateImpl is not
  // incomplete
  BaseTx::~BaseTx() = default;
}
