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
  // A consistent snapshot of the current service's identity, read from a
  // single KV version so the create-txid and endorsement are never drawn from
  // different ledger versions.
  struct CurrentServiceIdentity
  {
    // Current service's create-txid, or nullopt if not yet available
    // (service missing, no create-txid, or status != OPEN).
    std::optional<TxID> create_txid;

    // Current previous-identity endorsement entry in the live KV, or
    // nullopt if none has been written yet.
    std::optional<CoseEndorsement> endorsement;
  };

  struct INodeStateAccessor
  {
    virtual ~INodeStateAccessor() = default;

    [[nodiscard]] virtual bool is_part_of_network() const = 0;

    // Read the current service create-txid and the current previous-identity
    // endorsement from a single consistent KV snapshot, so a caller never
    // observes a create-txid and endorsement drawn from different ledger
    // versions (e.g. if a recovery commits between two separate reads).
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
