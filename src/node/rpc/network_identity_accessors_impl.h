// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/tables/service.h"
#include "node/historical_queries.h"
#include "node/retry_on_compacted_version_conflict.h"
#include "node/rpc/network_identity_accessors.h"
#include "node/rpc/node_interface.h"
#include "service/tables/signing_identities.h"
#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#include <fmt/format.h>
#include <memory>
#include <stdexcept>
#include <utility>

namespace ccf
{
  // Read the service record and the previous-identity endorsement from the
  // same read-only transaction (one KV snapshot), and only report the
  // create-txid when the service is OPEN. The endorsement is written in the
  // same transaction that opens the service, so this guarantees they belong to
  // the same service.
  inline CurrentServiceIdentity read_current_service_identity(
    ccf::kv::ReadOnlyTx& tx)
  {
    CurrentServiceIdentity result;

    auto* service_info_handle = tx.ro<ccf::Service>(ccf::Tables::SERVICE);
    auto service_info = service_info_handle->get();
    try
    {
      check_signing_identity_matches_service_cert(tx);
    }
    catch (const std::logic_error& e)
    {
      // The task running this read aborts the node on an escaping exception,
      // so explain the failure first. An ML-DSA service certificate without
      // its published signing identity comes from an unsupported build, see
      // the ML-DSA Service Identity section of the 7.x to 8.x migration guide.
      LOG_FATAL_FMT(
        "The service signing identities in the ledger are inconsistent with "
        "the service certificates: {}. This version cannot serve such a "
        "ledger after a live update; recover it instead.",
        e.what());
      throw;
    }
    // A node can advance to part-of-network before the service-opening tx has
    // been replicated. Until the service is OPEN, its create-txid (and the
    // endorsement written in the same tx) may be stale, so leave create_txid
    // unset and let the caller retry.
    if (
      service_info && service_info->current_service_create_txid.has_value() &&
      service_info->status == ServiceStatus::OPEN)
    {
      result.create_txid = service_info->current_service_create_txid;
    }

    result.endorsement = tx.ro<ccf::PreviousServiceIdentityEndorsement>(
                             ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
                           ->get(ccf::IdentityType::CLASSICAL);

    return result;
  }

  inline CoseEndorsement read_historical_service_endorsement(
    ccf::kv::ReadOnlyTx& tx, SeqNo seqno)
  {
    auto endorsement = tx.ro<ccf::PreviousServiceIdentityEndorsement>(
                           ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
                         ->get(ccf::IdentityType::CLASSICAL);
    if (!endorsement.has_value())
    {
      throw std::runtime_error(fmt::format(
        "COSE endorsement entry for seqno {} is missing from its "
        "historical state",
        seqno));
    }

    // Historical stores contain only this transaction's writes, so unchanged
    // PQ identities may be absent. Preserve the CLASSICAL-only read check.
    check_signing_identity_matches_service_cert(
      tx.ro<SigningIdentities>(Tables::SIGNING_IDENTITIES)
        ->get(IdentityType::CLASSICAL),
      tx.ro<Service>(Tables::SERVICE)->get(),
      IdentityType::CLASSICAL);
    return endorsement.value();
  }

  class NodeStateAccessor : public INodeStateAccessor
  {
  protected:
    AbstractNodeState& node_state;

  public:
    NodeStateAccessor(AbstractNodeState& node_state_) : node_state(node_state_)
    {}

    [[nodiscard]] bool is_part_of_network() const override
    {
      return node_state.is_part_of_network();
    }

    CurrentServiceIdentity get_current_service_identity() override
    {
      auto store = node_state.get_store();
      CurrentServiceIdentity identity;
      if (!ccf::retry_on_compacted_version_conflict(
            "Current service identity lookup", [&] {
              auto tx = store->create_read_only_tx();
              identity = read_current_service_identity(tx);
            }))
      {
        // Reported as not yet available, which the caller retries later
        LOG_FAIL_FMT(
          "Could not read current service identity after repeated compaction "
          "conflicts");
      }
      return identity;
    }
  };

  class HistoricalStateAccessor : public IHistoricalStateAccessor
  {
  protected:
    std::shared_ptr<historical::StateCacheImpl> historical_cache;

  public:
    HistoricalStateAccessor(
      std::shared_ptr<historical::StateCacheImpl> historical_cache_) :
      historical_cache(std::move(historical_cache_))
    {}

    std::optional<CoseEndorsement> get_endorsement_at(SeqNo seq) override
    {
      auto state = historical_cache->get_state_at(
        ccf::historical::CompoundHandle{
          ccf::historical::RequestNamespace::System, seq},
        seq);
      if (!state)
      {
        return std::nullopt;
      }
      if (!state->store)
      {
        throw std::runtime_error(fmt::format(
          "Historical state with seqno {} is loaded but its store is "
          "missing",
          seq));
      }
      auto htx = state->store->create_read_only_tx();
      return read_historical_service_endorsement(htx, seq);
    }
  };

  class TaskSchedulerImpl : public TaskScheduler
  {
  public:
    void add_delayed_task(
      std::function<void()> fn, std::chrono::milliseconds delay) override
    {
      auto task = ccf::tasks::make_basic_task(std::move(fn));
      ccf::tasks::add_delayed_task(task, delay);
    }
  };
}
