// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"
#include "service/tables/previous_service_identity.h"

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
    virtual std::optional<TxID> get_current_service_txid() = 0;

    // Current previous-identity endorsement entry in the live KV, or
    // nullopt if none has been written yet.
    virtual std::optional<CoseEndorsement> get_current_endorsement() = 0;
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

    virtual void add_delayed_task(
      std::function<void()> fn, std::chrono::milliseconds delay) = 0;
  };
}
