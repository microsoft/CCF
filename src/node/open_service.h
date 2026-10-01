// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/service/tables/service.h"
#include "ccf/tx.h"
#include "kv/committable_tx.h"
#include "node/internal_tables_access.h"
#include "node/ledger_secrets.h"
#include "node/share_manager.h"
#include "service/tables/shares.h"

#include <fmt/format.h>
#include <stdexcept>

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
    // procedure. Shares for the new ledger secret can only be issued now, once
    // the previous ledger secrets have been recovered.
    ShareManager::clear_submitted_recovery_shares(tx);

    if (!open_service(tx, share_manager, service_key))
    {
      throw std::logic_error("Service could not be opened");
    }
  }

  // Returns the hook, set on the historical encrypted ledger secret table when
  // private recovery begins, which points the ledger secret created at the end
  // of public recovery at the version at which the last ledger secret before
  // recovery is stored. That is the version of the opening of the recovered
  // service, which issues the recovery shares for the new ledger secret and is
  // the only write to that table which sets next_version (a rekey leaves it to
  // be inferred). An election can roll back an opening before it commits, and
  // a later primary write it again at another seqno, so every opening adjusts
  // the version, not only the first.
  inline ccf::kv::untyped::MapHook make_recovered_opening_secret_hook(
    std::shared_ptr<LedgerSecrets> ledger_secrets)
  {
    return EncryptedLedgerSecretsInfo::wrap_map_hook(
      [ledger_secrets = std::move(ledger_secrets)](
        ccf::kv::Version version, const EncryptedLedgerSecretsInfo::Write& w)
        -> ccf::kv::ConsensusHookPtr {
        if (!w.has_value())
        {
          throw std::logic_error(fmt::format(
            "Unexpected removal from {} table",
            Tables::ENCRYPTED_PAST_LEDGER_SECRET));
        }

        if (w->next_version.has_value())
        {
          ledger_secrets->adjust_previous_secret_stored_version(version);
        }

        return {nullptr};
      });
  }
}
