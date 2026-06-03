// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Narrow injection surfaces used by NetworkIdentitySubsystem.
// Production adapters live in network_identity_accessors_impl.h.

#include "ccf/tx_id.h"
#include "service/tables/previous_service_identity.h"
#include "tasks/task_system.h"

#include <chrono>
#include <functional>
#include <optional>

namespace ccf
{
  // Reads the live (non-historical) state needed to begin walking the
  // endorsement chain.
  struct INodeStateAccessor
  {
    virtual ~INodeStateAccessor() = default;

    [[nodiscard]] virtual bool is_part_of_network() const = 0;

    // Current service's create-txid, or nullopt if SERVICE is missing /
    // has no create_txid / is not yet OPEN.
    virtual std::optional<TxID> read_current_service_from() = 0;

    // Topmost previous-identity endorsement entry, or nullopt if none.
    virtual std::optional<CoseEndorsement> read_topmost_endorsement() = 0;
  };

  // Fetches a historical endorsement entry by its kv version.
  struct IHistoricalStateAccessor
  {
    virtual ~IHistoricalStateAccessor() = default;

    // Endorsement entry at the given historical kv version, or nullopt
    // if the historical state is not yet loaded. Implementations may
    // throw on hard errors (loaded state with missing store).
    virtual std::optional<CoseEndorsement> get_endorsement_at(SeqNo) = 0;
  };

  // Abstracts ccf::tasks so tests can drive the retry loop deterministically.
  struct TaskScheduler
  {
    virtual ~TaskScheduler() = default;

    virtual void add_task(std::function<void()> fn) = 0;

    virtual void add_delayed_task(
      std::function<void()> fn, std::chrono::milliseconds delay) = 0;
  };
}
