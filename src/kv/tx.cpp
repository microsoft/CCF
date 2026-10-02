// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/tx.h"

#include "ds/ccf_assert.h"
#include "ds/internal_logger.h"
#include "kv/compacted_version_conflict.h"
#include "kv/internal_table_names.h"
#include "kv/kv_types.h"
#include "kv/tx_pimpl.h"
#include "kv/untyped_map.h"

namespace ccf::kv
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

  void BaseTx::check_map_access(const std::string& map_name, AccessMode access)
  {
    const char* reason = nullptr;
    switch (pimpl->role)
    {
      case PrivateImpl::Role::Ordinary:
      {
        if (is_signature_table(map_name))
        {
          reason = "Live transactions cannot access signature tables";
        }
        break;
      }
      case PrivateImpl::Role::Reserved:
      {
        if (!is_signature_table(map_name) || access != AccessMode::WriteOnly)
        {
          reason =
            "Reserved transactions may only acquire write-only handles "
            "to signature tables";
        }
        break;
      }
      case PrivateImpl::Role::MaterialisedReadOnly:
      {
        if (!pimpl->store->check_rollback_count(pimpl->read_rollback_count))
        {
          throw CompactedVersionConflict(fmt::format(
            "Materialised state for map '{}' was invalidated by rollback",
            map_name));
        }
        if (access != AccessMode::ReadOnly && access != AccessMode::Diff)
        {
          reason =
            "Materialised read transactions may only acquire read-only "
            "or diff handles";
        }
        break;
      }
    }

    if (reason != nullptr)
    {
      const auto message =
        fmt::format("Access to map '{}' denied: {}", map_name, reason);
      LOG_FAIL_FMT("{}", message);
      throw MapAccessDenied(message);
    }
  }

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
    const std::string& map_name,
    bool track_deletes_on_missing_keys,
    AccessMode access)
  {
    check_map_access(map_name, access);

    auto& read_txid = pimpl->read_txid;

    if (!read_txid.has_value())
    {
      // Grab opacity version that all Maps should be queried at.
      // Note: It is by design that we delay acquiring a read version to now
      // rather than earlier, at Tx construction. This is to minimise the
      // window during which concurrent transactions can write to the same map
      // and cause this transaction to conflict on commit.
      auto p = pimpl->store->current_txid_and_commit_term();
      read_txid = p.first;
      pimpl->commit_view = p.second;
    }

    auto abstract_map = pimpl->store->get_map(read_txid->seqno, map_name);
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
      auto new_map =
        std::make_shared<ccf::kv::untyped::Map>(pimpl->store, map_name);
      pimpl->created_maps[map_name] = new_map;

      abstract_map = new_map;
    }

    auto untyped_map =
      std::dynamic_pointer_cast<ccf::kv::untyped::Map>(abstract_map);
    if (untyped_map == nullptr)
    {
      throw std::logic_error(
        fmt::format("Map {} has unexpected type", map_name));
    }

    auto change_set = untyped_map->create_change_set(
      read_txid->seqno, track_deletes_on_missing_keys);
    // Rollback can replace a map between the access check and snapshot capture.
    if (pimpl->role == PrivateImpl::Role::MaterialisedReadOnly)
    {
      check_map_access(map_name, access);
    }
    return {abstract_map, std::move(change_set)};
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
    auto& read_txid = pimpl->read_txid;
    if (!read_txid.has_value())
    {
      throw std::logic_error(
        fmt::format("read_txid should have already been set"));
    }
    throw CompactedVersionConflict(fmt::format(
      "Unable to retrieve state over map {} at {}",
      map_name,
      read_txid->seqno));
  }

  BaseTx::BaseTx(AbstractStore* store_)
  {
    pimpl = std::make_unique<PrivateImpl>();
    pimpl->store = store_;
  }

  ReadOnlyTx::ReadOnlyTx(
    AbstractStore* store_,
    ccf::SeqNo read_version,
    Version read_rollback_count) :
    BaseTx(store_)
  {
    pimpl->role = PrivateImpl::Role::MaterialisedReadOnly;
    pimpl->read_txid = TxID(ccf::VIEW_UNKNOWN, read_version);
    pimpl->read_rollback_count = read_rollback_count;
  }

  TxDiff::TxDiff(
    AbstractStore* store_,
    ccf::SeqNo read_version,
    Version read_rollback_count) :
    BaseTx(store_)
  {
    pimpl->role = PrivateImpl::Role::MaterialisedReadOnly;
    pimpl->read_txid = TxID(ccf::VIEW_UNKNOWN, read_version);
    pimpl->read_rollback_count = read_rollback_count;
  }

  // Use default destructor, but instantiate here where PrivateImpl is not
  // incomplete
  BaseTx::~BaseTx() = default;
}
