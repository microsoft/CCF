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
  // The current service's identity, with the create-txid and endorsement read
  // together from the same KV transaction.
  struct CurrentServiceIdentity
  {
    std::optional<TxID> create_txid;

    std::optional<CoseEndorsement> endorsement;
  };

  struct INodeStateAccessor
  {
    virtual ~INodeStateAccessor() = default;

    [[nodiscard]] virtual bool is_part_of_network() const = 0;

    // Read the current service create-txid and previous-identity endorsement
    // together, only when the service status is OPEN. This guarantees they
    // belong to the same service, because the endorsement is written in the
    // same transaction that opens the service.
    virtual CurrentServiceIdentity get_current_service_identity() = 0;
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
