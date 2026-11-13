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
  // Read the service record and the previous-identity endorsements from the
  // same read-only transaction (one KV snapshot), and only report the
  // create-txid when the service is OPEN. The endorsements are written in the
  // same transaction that opens the service, so this guarantees they belong to
  // the same service.
  inline CurrentServiceIdentity read_current_service_identity(
    ccf::kv::ReadOnlyTx& tx)
  {
    CurrentServiceIdentity result;

    // A node can advance to part-of-network before the service-opening tx has
    // been replicated. Until the service is OPEN, its create-txid (and the
    // endorsement written in the same tx) may be stale, so report nothing and
    // let the caller retry.
    const auto service_info = tx.ro<ccf::Service>(ccf::Tables::SERVICE)->get();
    const bool service_open = service_info.has_value() &&
      service_info->current_service_create_txid.has_value() &&
      service_info->status == ServiceStatus::OPEN;
    if (!service_open)
    {
      return result;
    }

    try
    {
      check_signing_identity_matches_service_cert(tx);
    }
    catch (const std::logic_error& e)
    {
      // Logged here in case the call site does not handle the exception
      // properly: this is a broken invariant and must not be recovered from.
      LOG_FATAL_FMT(
        "The service signing identities in the ledger are inconsistent with "
        "the service certificates: {}. This version cannot serve such a "
        "ledger after a live update; recover it instead.",
        e.what());
      throw;
    }

    result.create_txid = service_info->current_service_create_txid;
    auto* endorsements = tx.ro<ccf::PreviousServiceIdentityEndorsement>(
      ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT);
    result.endorsement = endorsements->get(ccf::IdentityType::CLASSICAL);
    // A PQ endorsement belongs to the current service only if the transaction
    // which opened it wrote the PQ endorsement with the CLASSICAL one
    const auto classical_version =
      endorsements->get_version_of_previous_write(ccf::IdentityType::CLASSICAL);
    if (
      classical_version.has_value() &&
      classical_version ==
        endorsements->get_version_of_previous_write(ccf::IdentityType::PQ))
    {
      result.pq_endorsement = endorsements->get(ccf::IdentityType::PQ);
    }
    return result;
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

    std::optional<WrittenEndorsements> get_endorsements_at(SeqNo seq) override
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
      // The historical store holds the writes of the transaction at seq only
      auto htx = state->store->create_read_only_tx();
      auto* endorsements =
        htx.template ro<ccf::PreviousServiceIdentityEndorsement>(
          ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT);
      auto endorsement = endorsements->get(ccf::IdentityType::CLASSICAL);
      if (!endorsement.has_value())
      {
        throw std::runtime_error(fmt::format(
          "COSE endorsement entry for seqno {} is missing from its "
          "historical state",
          seq));
      }
      return WrittenEndorsements{
        .classical = std::move(endorsement.value()),
        .pq = endorsements->get(ccf::IdentityType::PQ)};
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
