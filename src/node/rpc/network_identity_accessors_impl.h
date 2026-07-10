// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/tables/service.h"
#include "node/historical_queries.h"
#include "node/rpc/network_identity_accessors.h"
#include "node/rpc/node_interface.h"
#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#include <fmt/format.h>
#include <memory>
#include <stdexcept>
#include <utility>

namespace ccf
{
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
      // Read the service record and the previous-identity endorsement from the
      // SAME read-only transaction (one KV snapshot), and only report them when
      // the service is OPEN. The endorsement is written in the same transaction
      // that opens the service, so this guarantees they belong to the same
      // service.
      auto store = node_state.get_store();
      auto tx = store->create_read_only_tx();

      CurrentServiceIdentity result;

      auto* service_info_handle =
        tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
      auto service_info = service_info_handle->get();
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

      result.endorsement =
        tx.template ro<ccf::PreviousServiceIdentityEndorsement>(
            ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
          ->get();

      return result;
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
      auto endorsement =
        htx
          .template ro<ccf::PreviousServiceIdentityEndorsement>(
            ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
          ->get();
      if (!endorsement.has_value())
      {
        throw std::runtime_error(fmt::format(
          "COSE endorsement entry for seqno {} is missing from its "
          "historical state",
          seq));
      }
      return endorsement;
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
