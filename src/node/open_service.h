// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/service/tables/service.h"
#include "ccf/tx.h"
#include "kv/committable_tx.h"
#include "node/internal_tables_access.h"
#include "node/share_manager.h"

#include <format>
#include <stdexcept>
#include <utility>

namespace ccf
{
  // Requests that a snapshot be taken at the next signature, so that a
  // working snapshot signed by the current service identity exists.
  inline void trigger_snapshot(ccf::kv::Tx& tx)
  {
    auto* committable_tx = dynamic_cast<ccf::kv::CommittableTx*>(&tx);
    if (committable_tx == nullptr)
    {
      throw std::logic_error("Could not cast tx to CommittableTx");
    }
    committable_tx->set_tx_flag(
      ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
  }

  // Opens the service: issues recovery shares for the current ledger secret,
  // marks the service open, endorses the previous service identity with the
  // current one, and requests a snapshot. Shared by service creation and the
  // end of recovery; the caller is responsible for checking the node is
  // entitled to open (it is the primary) and for any state-specific
  // preconditions. Returns false if the service could not be opened or the
  // previous identity could not be endorsed (both already logged), leaving
  // the caller to decide whether that is fatal.
  [[nodiscard]] inline bool open_service(
    ccf::kv::Tx& tx,
    ShareManager& share_manager,
    const ccf::crypto::ECKeyPair_OpenSSL& service_key)
  {
    share_manager.issue_recovery_shares(tx);

    if (
      !InternalTablesAccess::open_service(tx) ||
      !InternalTablesAccess::endorse_previous_identity(tx, service_key))
    {
      return false;
    }

    trigger_snapshot(tx);
    return true;
  }

  // Opens the service at the end of a recovery, once the private ledger has
  // been replayed. Throws if the service is not waiting for recovery shares,
  // so that the transition happens at most once even if two nodes believe
  // they are primary. Clears the submitted shares before opening.
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
        throw std::logic_error(std::format(
          "Error in {}: no value in {}", __func__, Tables::SERVICE));
      }

      if (active_service->status != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
      {
        throw std::logic_error(std::format(
          "Error in {}: current service status is {}",
          __func__,
          std::to_underlying(active_service->status)));
      }
    }

    // Clear recovery shares that were submitted to initiate the recovery
    // procedure. Shares for the new ledger secret can only be issued now, once
    // the previous ledger secrets have been recovered.
    ShareManager::clear_submitted_recovery_shares(tx);

    if (!open_service(tx, share_manager, service_key))
    {
      throw std::logic_error("Service could not be opened");
    }
  }
}
