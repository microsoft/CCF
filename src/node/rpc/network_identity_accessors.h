// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"
#include "service/tables/previous_service_identity.h"
#include "tasks/task_system.h"

#include <chrono>
#include <functional>
#include <optional>

namespace ccf
{
  struct INodeStateAccessor
  {
    virtual ~INodeStateAccessor() = default;

    [[nodiscard]] virtual bool is_part_of_network() const = 0;

    // Current service's create-txid, or nullopt if not yet available.
    virtual std::optional<TxID> read_current_service_from() = 0;

    // Topmost previous-identity endorsement entry, or nullopt if none.
    virtual std::optional<CoseEndorsement> read_topmost_endorsement() = 0;
  };

  struct IHistoricalStateAccessor
  {
    virtual ~IHistoricalStateAccessor() = default;

    // Endorsement entry at the given historical kv version, or nullopt
    // if the historical state is not yet loaded. Implementations may
    // throw on hard errors.
    virtual std::optional<CoseEndorsement> get_endorsement_at(SeqNo) = 0;
  };

  struct TaskScheduler
  {
    virtual ~TaskScheduler() = default;

    virtual void add_task(std::function<void()> fn) = 0;

    virtual void add_delayed_task(
      std::function<void()> fn, std::chrono::milliseconds delay) = 0;
  };
}
