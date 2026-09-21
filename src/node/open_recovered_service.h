// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/service/tables/service.h"
#include "ccf/tx.h"
#include "kv/committable_tx.h"
#include "node/internal_tables_access.h"
#include "node/share_manager.h"

#include <fmt/format.h>
#include <stdexcept>

namespace ccf
{
  // Opens the service at the end of a recovery, once the private ledger has
  // been replayed. Only the node which can replicate (the primary) may do
  // this; the caller is responsible for that check. Throws if the service is
  // not waiting for recovery shares, so that the transition happens at most
  // once even if two nodes believe they are primary.
  inline void open_recovered_service(
    ccf::kv::Tx& tx,
    ShareManager& share_manager,
    const ccf::crypto::ECKeyPair_OpenSSL& service_key)
  {
    {
      auto* service = tx.ro<ccf::Service>(Tables::SERVICE);
      auto active_service = service->get();

      if (!active_service.has_value())
      {
        throw std::logic_error(fmt::format(
          "Error in {}: no value in {}", __func__, Tables::SERVICE));
      }

      if (active_service->status != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
      {
        throw std::logic_error(fmt::format(
          "Error in {}: current service status is {}",
          __func__,
          active_service->status));
      }
    }

    // Clear recovery shares that were submitted to initiate the recovery
    // procedure
    ShareManager::clear_submitted_recovery_shares(tx);

    // Shares for the new ledger secret can only be issued now, once the
    // previous ledger secrets have been recovered
    share_manager.issue_recovery_shares(tx);

    if (
      !InternalTablesAccess::open_service(tx) ||
      !InternalTablesAccess::endorse_previous_identity(tx, service_key))
    {
      throw std::logic_error("Service could not be opened");
    }

    // Trigger a snapshot (at next signature) to ensure we have a working
    // snapshot signed by the current (now new) service identity, in case we
    // need to recover soon again.
    auto* committable_tx = dynamic_cast<ccf::kv::CommittableTx*>(&tx);
    if (committable_tx == nullptr)
    {
      throw std::logic_error("Could not cast tx to CommittableTx");
    }
    committable_tx->set_tx_flag(
      ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
  }
}
