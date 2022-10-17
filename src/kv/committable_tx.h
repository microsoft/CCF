// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apply_changes.h"
#include "ccf/ds/hex.h"
#include "ccf/tx.h"
#include "kv/tx_pimpl.h"
#include "kv_serialiser.h"
#include "kv_types.h"
#include "node/rpc/claims.h"

#include <list>

namespace kv
{
  class CommittableTx : public Tx, public AbstractChangeContainer
  {
  public:
    using TxFlags = uint8_t;

    enum class Flag : TxFlags
    {
      LEDGER_CHUNK_AT_NEXT_SIGNATURE = 0x01,
      SNAPSHOT_AT_NEXT_SIGNATURE = 0x02,
      LEDGER_CHUNK_BEFORE_THIS_TX = 0x04,
    };

  protected:
    bool committed = false;
    bool success = false;

    Version version = NoVersion;

    kv::TxHistory::RequestID req_id;

    TxFlags flags = 0;
    SerialisedEntryFlags entry_flags = 0;

    std::vector<uint8_t> serialise(
      crypto::Sha256Hash& commit_evidence_digest,
      std::string& commit_evidence,
      const ccf::ClaimsDigest& claims_digest_,
      bool include_reads = false)
    {
      if (!committed)
        throw std::logic_error("Transaction not yet committed");

      if (!success)
        throw std::logic_error("Transaction aborted");

      if (claims_digest_.empty())
        throw std::logic_error("Missing claims");

      // If no transactions made changes, return a zero length vector.
      const bool any_changes =
        std::any_of(all_changes.begin(), all_changes.end(), [](const auto& it) {
          return it.second.changeset->has_writes();
        });

      if (!any_changes)
      {
        return {};
      }

      auto e = pimpl->store->get_encryptor();
      if (e == nullptr)
      {
        throw KvSerialiserException("No encryptor set");
      }

      auto commit_nonce = e->get_commit_nonce({pimpl->commit_view, version});
      commit_evidence = fmt::format(
        "ce:{}.{}:{}", pimpl->commit_view, version, ds::to_hex(commit_nonce));
      LOG_TRACE_FMT("Commit evidence: {}", commit_evidence);
      crypto::Sha256Hash tx_commit_evidence_digest(commit_evidence);
      commit_evidence_digest = tx_commit_evidence_digest;
      auto entry_type = EntryType::WriteSetWithCommitEvidenceAndClaims;

      if (flag_enabled(Flag::LEDGER_CHUNK_BEFORE_THIS_TX))
      {
        entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_BEFORE;
      }

      KvStoreSerialiser replicated_serialiser(
        e,
        {pimpl->commit_view, version},
        entry_type,
        entry_flags,
        tx_commit_evidence_digest,
        claims_digest_);

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
      const ccf::ClaimsDigest& claims = ccf::empty_claims(),
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
      if (!pimpl->created_maps.empty())
        this->pimpl->store->lock();

      kv::ConsensusHookPtrs hooks;

      std::optional<Version> new_maps_conflict_version = std::nullopt;

      bool track_deletes_on_missing_keys = false;
      auto c = apply_changes(
        all_changes,
        version_resolver == nullptr ?
          [&](bool has_new_map) {
            return pimpl->store->next_version(has_new_map);
          } :
          version_resolver,
        hooks,
        pimpl->created_maps,
        new_maps_conflict_version,
        track_read_versions,
        track_deletes_on_missing_keys);

      if (!pimpl->created_maps.empty())
        this->pimpl->store->unlock();

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

        if (flag_enabled(Flag::LEDGER_CHUNK_AT_NEXT_SIGNATURE))
        {
          pimpl->store->set_flag(
            AbstractStore::Flag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);
          // This transaction indicates to the store that the next signature
          // should trigger a new ledger chunk, but *this* transaction does not
          // create a new ledger chunk
          unset_flag(CommittableTx::Flag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);
        }

        if (flag_enabled(Flag::SNAPSHOT_AT_NEXT_SIGNATURE))
        {
          pimpl->store->set_flag(
            AbstractStore::Flag::SNAPSHOT_AT_NEXT_SIGNATURE);
          unset_flag(CommittableTx::Flag::SNAPSHOT_AT_NEXT_SIGNATURE);
        }

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

          return pimpl->store->commit(
            {pimpl->commit_view, version},
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

      return pimpl->commit_view;
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

      if (!pimpl->read_txid.has_value())
      {
        // Transaction did not get a handle on any map.
        return std::nullopt;
      }

      // A committed tx is read-only (i.e. no write to any map) if it was not
      // assigned a version when it was committed
      if (version == NoVersion)
      {
        // Read-only transaction
        return pimpl->read_txid.value();
      }
      else
      {
        // Write transaction
        return TxID(pimpl->commit_view, version);
      }
    }

    void set_change_list(OrderedChanges&& change_list_, Term term_) override
    {
      // if all_changes is not empty then any coinciding keys will not be
      // overwritten
      all_changes.merge(change_list_);
      pimpl->commit_view = term_;
    }

    void set_view(ccf::View view_)
    {
      pimpl->commit_view = view_;
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
      if (pimpl->read_txid.has_value())
      {
        throw std::logic_error("Read TxID already set");
      }
      pimpl->read_txid = tx_id;
      pimpl->commit_view = commit_view_;
    }

    void set_root_at_read_version(const crypto::Sha256Hash& r)
    {
      root_at_read_version = r;
    }

    virtual void set_flag(Flag flag)
    {
      flags |= static_cast<uint8_t>(flag);
    }

    virtual void unset_flag(Flag flag)
    {
      flags &= ~static_cast<uint8_t>(flag);
    }

    virtual bool flag_enabled(Flag f) const
    {
      return (flags & static_cast<uint8_t>(f)) != 0;
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
      pimpl->commit_view = reserved_tx_id.term;
      pimpl->read_txid = TxID(read_term, reserved_tx_id.version - 1);
    }

    // Used by frontend to commit reserved transactions
    PendingTxInfo commit_reserved()
    {
      if (committed)
        throw std::logic_error("Transaction already committed");

      if (all_changes.empty())
        throw std::logic_error("Reserved transaction cannot be empty");

      std::vector<ConsensusHookPtr> hooks;
      bool track_read_versions = false;
      bool track_deletes_on_missing_keys = false;
      auto c = apply_changes(
        all_changes,
        [this](bool) { return std::make_tuple(version, version - 1); },
        hooks,
        pimpl->created_maps,
        version,
        track_read_versions,
        track_deletes_on_missing_keys);
      success = c.has_value();

      if (!success)
        throw std::logic_error("Failed to commit reserved transaction");

      crypto::Sha256Hash commit_evidence_digest;
      std::string commit_evidence;

      // This is a signature and, if the ledger chunking or snapshot flags are
      // enabled, we want the host to create a chunk when it sees this entry.
      // version_lock held by Store::commit
      if (pimpl->store->must_force_ledger_chunk_unsafe(version))
      {
        entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_AFTER;
        LOG_DEBUG_FMT(
          "Forcing ledger chunk for signature at {}.{}",
          pimpl->commit_view,
          version);
      }

      committed = true;
      auto claims = ccf::empty_claims();
      auto data = serialise(commit_evidence_digest, commit_evidence, claims);

      // Reset ledger chunk flag in the store
      pimpl->store->unset_flag_unsafe(
        AbstractStore::Flag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);

      return {
        CommitResult::SUCCESS,
        std::move(data),
        ccf::empty_claims(),
        std::move(commit_evidence_digest),
        std::move(hooks)};
    }
  };
}
