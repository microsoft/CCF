// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apply_changes.h"
#include "ccf/tx.h"
#include "kv_serialiser.h"
#include "kv_types.h"
#include "node/rpc/claims.h"

#include <list>

namespace kv
{
  class CommittableTx : public Tx, public AbstractChangeContainer
  {
  protected:
    bool committed = false;
    bool success = false;

    Version version = NoVersion;

    kv::TxHistory::RequestID req_id;

    std::vector<uint8_t> serialise(
      crypto::Sha256Hash& commit_evidence_digest,
      std::string& commit_evidence,
      const ccf::ClaimsDigest& claims_digest = ccf::no_claims(),
      bool include_reads = false)
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      // If no transactions made changes, return a zero length vector.
      const bool any_changes =
        std::any_of(all_changes.begin(), all_changes.end(), [](const auto& it) {
          return it.second.changeset->has_writes();
        });

      if (!any_changes)
      {
        return {};
      }

      auto e = store->get_encryptor();
      if (e == nullptr)
        throw KvSerialiserException("No encryptor set");
      auto commit_nonce = e->get_commit_nonce({commit_view, version});
      commit_evidence = fmt::format(
        "ce:{}.{}:{}", commit_view, version, ds::to_hex(commit_nonce));
      LOG_TRACE_FMT("Commit evidence: {}", commit_evidence);
      crypto::Sha256Hash tx_commit_evidence_digest(commit_evidence);
      commit_evidence_digest = tx_commit_evidence_digest;
      auto entry_type = claims_digest.empty() ?
        EntryType::WriteSetWithCommitEvidence :
        EntryType::WriteSetWithCommitEvidenceAndClaims;

      LOG_TRACE_FMT(
        "Serialising claim digest {} {}",
        claims_digest.value(),
        claims_digest.empty());
      KvStoreSerialiser replicated_serialiser(
        e,
        {commit_view, version},
        entry_type,
        tx_commit_evidence_digest,
        claims_digest);

      // Process in security domain order
      for (auto domain : {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
      {
        for (const auto& it : all_changes)
        {
          const auto& map = it.second.map;
          const auto& changeset = it.second.changeset;
          if (
            map->get_security_domain() == domain && map->is_replicated() &&
            changeset->has_writes())
          {
            map->serialise_changes(
              changeset.get(), replicated_serialiser, include_reads);
          }
        }
      }

      // Return serialised Tx.
      return replicated_serialiser.get_raw_data();
    }

  public:
    CommittableTx(AbstractStore* _store) : Tx(_store) {}

    /** Commit this transaction to the local KV and submit it to consensus for
     * replication
     *
     * A transaction can either succeed and replicate
     * (`kv::CommitResult::SUCCESS`), fail because of a conflict with other
     * transactions (`kv::CommitResult::FAIL_CONFLICT`), or succeed locally, but
     * fail to replicate (`kv::CommitResult::FAIL_NO_REPLICATE`).
     *
     * Transactions that fail are rolled back, no matter the reason.
     *
     * @return transaction outcome
     */
    CommitResult commit(
      const ccf::ClaimsDigest& claims = ccf::no_claims(),
      bool track_read_versions = false,
      std::function<std::tuple<Version, Version>(bool has_new_map)>
        version_resolver = nullptr,
      std::function<void(
        const std::vector<uint8_t>& write_set,
        const std::string& commit_evidence)> write_set_observer = nullptr)
    {
      if (committed)
        throw std::logic_error("Transaction already committed");

      if (all_changes.empty())
      {
        committed = true;
        success = true;
        return CommitResult::SUCCESS;
      }

      // If this transaction creates any maps, ensure that commit gets a
      // consistent snapshot of the existing maps
      if (!created_maps.empty())
        this->store->lock();

      kv::ConsensusHookPtrs hooks;

      std::optional<Version> new_maps_conflict_version = std::nullopt;

      auto c = apply_changes(
        all_changes,
        version_resolver == nullptr ?
          [&](bool has_new_map) { return store->next_version(has_new_map); } :
          version_resolver,
        hooks,
        created_maps,
        new_maps_conflict_version,
        track_read_versions);

      if (!created_maps.empty())
        this->store->unlock();

      success = c.has_value();

      if (!success)
      {
        // This Tx is now in a dead state. Caller should create a new Tx and try
        // again.
        LOG_TRACE_FMT("Could not commit transaction due to conflict");
        return CommitResult::FAIL_CONFLICT;
      }
      else
      {
        committed = true;
        version = c.value();

        if (version == NoVersion)
        {
          // Read-only transaction
          return CommitResult::SUCCESS;
        }

        // From here, we have received a unique commit version and made
        // modifications to our local kv. If we fail in any way, we cannot
        // recover.
        try
        {
          crypto::Sha256Hash commit_evidence_digest;
          std::string commit_evidence;
          auto data =
            serialise(commit_evidence_digest, commit_evidence, claims);

          if (data.empty())
          {
            return CommitResult::SUCCESS;
          }

          if (write_set_observer != nullptr)
          {
            write_set_observer(data, commit_evidence);
          }

          auto claims_ = claims;

          return store->commit(
            {commit_view, version},
            std::make_unique<MovePendingTx>(
              std::move(data),
              std::move(claims_),
              std::move(commit_evidence_digest),
              std::move(hooks)),
            false);
        }
        catch (const std::exception& e)
        {
          committed = false;

          LOG_FAIL_FMT("Error during serialisation");
          LOG_DEBUG_FMT("Error during serialisation: {}", e.what());

          // Discard original exception type, throw as now fatal
          // KvSerialiserException
          throw KvSerialiserException(e.what());
        }
      }
    }

    /** Get version at which this transaction was committed.
     *
     * Throws if this is not successfully committed - should only be called if
     * an earlier call to commit() returned CommitResult::SUCCESS
     *
     * @return Commit version
     */
    Version commit_version()
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      return version;
    }

    /** Get term in which this transaction was committed.
     *
     * Throws if this is not successfully committed - should only be called if
     * an earlier call to commit() returned CommitResult::SUCCESS
     *
     * @return Commit term
     */
    Version commit_term()
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      return commit_view;
    }

    /** Version for the transaction set
     *
     * @return Committed version, or `kv::NoVersion` otherwise
     */
    Version get_version()
    {
      return version;
    }

    std::optional<TxID> get_txid()
    {
      if (!committed)
      {
        throw std::logic_error("Transaction not yet committed");
      }

      if (!read_txid.has_value())
      {
        // Transaction did not get a handle on any map.
        return std::nullopt;
      }

      // A committed tx is read-only (i.e. no write to any map) if it was not
      // assigned a version when it was committed
      if (version == NoVersion)
      {
        // Read-only transaction
        return read_txid.value();
      }
      else
      {
        // Write transaction
        return TxID(commit_view, version);
      }
    }

    void set_change_list(OrderedChanges&& change_list_, Term term_) override
    {
      // if all_changes is not empty then any coinciding keys will not be
      // overwritten
      all_changes.merge(change_list_);
      commit_view = term_;
    }

    void set_view(ccf::View view_)
    {
      commit_view = view_;
    }

    void set_req_id(const kv::TxHistory::RequestID& req_id_)
    {
      req_id = req_id_;
    }

    const kv::TxHistory::RequestID& get_req_id()
    {
      return req_id;
    }

    void set_read_txid(const TxID& tx_id, Term commit_view_)
    {
      if (read_txid.has_value())
      {
        throw std::logic_error("Read TxID already set");
      }
      read_txid = tx_id;
      commit_view = commit_view_;
    }

    void set_root_at_read_version(const crypto::Sha256Hash& r)
    {
      root_at_read_version = r;
    }
  };

  // Used by frontend for reserved transactions. These are constructed with a
  // pre-reserved Version, and _must succeed_ to fulfil this version. Otherwise
  // they create a hole in the transaction order, and no future transactions can
  // complete. These transactions are used internally by CCF for the sole
  // purpose of recording node signatures and are safe in this particular
  // situation because they never perform any reads and therefore can
  // never conflict.
  class ReservedTx : public CommittableTx
  {
  public:
    ReservedTx(
      AbstractStore* _store, Term read_term, const TxID& reserved_tx_id) :
      CommittableTx(_store)
    {
      version = reserved_tx_id.version;
      commit_view = reserved_tx_id.term;
      read_txid = TxID(read_term, reserved_tx_id.version - 1);
    }

    // Used by frontend to commit reserved transactions
    PendingTxInfo commit_reserved()
    {
      if (committed)
        throw std::logic_error("Transaction already committed");

      if (all_changes.empty())
        throw std::logic_error("Reserved transaction cannot be empty");

      std::vector<ConsensusHookPtr> hooks;
      auto c = apply_changes(
        all_changes,
        [this](bool) { return std::make_tuple(version, version - 1); },
        hooks,
        created_maps,
        version);
      success = c.has_value();

      if (!success)
        throw std::logic_error("Failed to commit reserved transaction");

      crypto::Sha256Hash commit_evidence_digest;
      std::string commit_evidence;

      committed = true;
      auto data = serialise(commit_evidence_digest, commit_evidence);

      return {
        CommitResult::SUCCESS,
        std::move(data),
        ccf::no_claims(),
        std::move(commit_evidence_digest),
        std::move(hooks)};
    }
  };
}
