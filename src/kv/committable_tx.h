// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apply_changes.h"
#include "ccf/ds/hex.h"
#include "ccf/tx.h"
#include "ds/internal_logger.h"
#include "kv/tx_pimpl.h"
#include "kv_serialiser.h"
#include "kv_types.h"
#include "node/rpc/claims.h"

#include <list>

namespace ccf::kv
{
  class CommittableTx : public Tx
  {
  public:
    using TxFlags = uint8_t;

    enum class TxFlag : TxFlags
    {
      LEDGER_CHUNK_AT_NEXT_SIGNATURE = 0x01,
      SNAPSHOT_AT_NEXT_SIGNATURE = 0x02,
      LEDGER_CHUNK_BEFORE_THIS_TX = 0x04,
    };

  protected:
    class MapSetLockGuard
    {
    private:
      AbstractStore& store;
      const bool locked;

    public:
      MapSetLockGuard(AbstractStore& store_, bool should_lock) :
        store(store_),
        locked(should_lock)
      {
        if (locked)
        {
          store.lock_map_set();
        }
      }

      ~MapSetLockGuard()
      {
        if (locked)
        {
          store.unlock_map_set();
        }
      }

      MapSetLockGuard(const MapSetLockGuard&) = delete;
      MapSetLockGuard& operator=(const MapSetLockGuard&) = delete;
    };

    bool committed = false;
    bool success = false;

    Version version = NoVersion;

    TxFlags flags = 0;
    SerialisedEntryFlags entry_flags = 0;

    void serialise_all_changes(
      KvStoreSerialiser& serialiser, bool include_reads)
    {
      // Process in security domain order
      for (auto domain : {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
      {
        for (const auto& it : all_changes)
        {
          const auto& map = it.second.map;
          const auto& changeset = it.second.changeset;
          if (map->get_security_domain() == domain && changeset->has_writes())
          {
            map->serialise_changes(changeset.get(), serialiser, include_reads);
          }
        }
      }
    }

    [[nodiscard]] bool has_writes() const
    {
      return std::any_of(
        all_changes.begin(), all_changes.end(), [](const auto& it) {
          return it.second.changeset->has_writes();
        });
    }

    size_t projected_serialised_size(
      const ccf::ClaimsDigest& claims_digest_, bool include_reads = false)
    {
      if (claims_digest_.empty())
      {
        throw std::logic_error("Missing claims");
      }

      auto e = pimpl->store->get_encryptor();
      if (e == nullptr)
      {
        throw KvSerialiserException("No encryptor set");
      }

      SizeKvStoreSerialiser size_serialiser(
        e,
        TxID{pimpl->commit_view, NoVersion},
        EntryType::WriteSetWithCommitEvidenceAndClaims,
        entry_flags,
        // Both digests are fixed-size, so their values do not affect the
        // projected size.
        ccf::crypto::Sha256Hash{},
        claims_digest_);

      serialise_all_changes(size_serialiser, include_reads);

      return size_serialiser.get_serialised_size();
    }

    std::vector<uint8_t> serialise(
      ccf::crypto::Sha256Hash& commit_evidence_digest,
      std::string& commit_evidence,
      const ccf::ClaimsDigest& claims_digest_,
      size_t max_transaction_size,
      bool include_reads = false)
    {
      if (!committed)
      {
        throw std::logic_error("Transaction not yet committed");
      }

      if (!success)
      {
        throw std::logic_error("Transaction aborted");
      }

      if (claims_digest_.empty())
      {
        throw std::logic_error("Missing claims");
      }

      if (!has_writes())
      {
        return {};
      }

      auto e = pimpl->store->get_encryptor();
      if (e == nullptr)
      {
        throw KvSerialiserException("No encryptor set");
      }

      commit_evidence = e->get_commit_evidence({pimpl->commit_view, version});
      LOG_TRACE_FMT("Commit evidence: {}", commit_evidence);
      ccf::crypto::Sha256Hash tx_commit_evidence_digest(commit_evidence);
      commit_evidence_digest = tx_commit_evidence_digest;

      if (tx_flag_enabled(TxFlag::LEDGER_CHUNK_BEFORE_THIS_TX))
      {
        entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_BEFORE;
      }

      RawKvStoreSerialiser serialiser(
        e,
        {pimpl->commit_view, version},
        EntryType::WriteSetWithCommitEvidenceAndClaims,
        entry_flags,
        tx_commit_evidence_digest,
        claims_digest_,
        false /* historical_hint */,
        max_transaction_size);

      serialise_all_changes(serialiser, include_reads);
      return serialiser.get_raw_data();
    }

  public:
    CommittableTx(AbstractStore* _store) : Tx(_store) {}

    using WriteSetObserver = std::function<void(
      const ccf::crypto::Sha256Hash& write_set_digest,
      const std::string& commit_evidence)>;

    /** Commit this transaction to the local KV and submit it to consensus for
     * replication
     *
     * A transaction can either succeed and replicate
     * (`ccf::kv::CommitResult::SUCCESS`), fail because of a conflict with other
     * transactions (`ccf::kv::CommitResult::FAIL_CONFLICT`), or fail to
     * replicate (`ccf::kv::CommitResult::FAIL_NO_REPLICATE`). A transaction
     * whose commit term is stale is rejected before its writes are applied.
     *
     * Transactions that fail are rolled back, no matter the reason.
     *
     * @return transaction outcome
     */
    CommitResult commit(
      const ccf::ClaimsDigest& claims = ccf::empty_claims(),
      WriteSetObserver write_set_observer = nullptr)
    {
      if (committed)
      {
        throw std::logic_error("Transaction already committed");
      }

      if (all_changes.empty())
      {
        committed = true;
        success = true;
        return CommitResult::SUCCESS;
      }

      std::optional<size_t> projected_entry_size = std::nullopt;

      // Measure the write set and reject oversized entries before any change is
      // applied. This pass performs no allocations or copies. Actual
      // serialisation is deferred until after conflict detection.
      if (has_writes())
      {
        const auto max_transaction_size =
          pimpl->store->get_max_transaction_size();
        projected_entry_size = projected_serialised_size(claims);
        if (projected_entry_size.value() > max_transaction_size)
        {
          throw MaxTransactionSizeExceeded(describe_serialised_entry_size_error(
            projected_entry_size.value(), max_transaction_size));
        }
      }

      // If this transaction creates any maps, ensure that commit gets a
      // consistent snapshot of the existing map set
      const bool maps_created = !pimpl->created_maps.empty();

      ccf::kv::ConsensusHookPtrs hooks;

      std::optional<Version> new_maps_conflict_version = std::nullopt;

      bool track_deletes_on_missing_keys = false;
      bool commit_term_changed = false;
      std::optional<Version> c;
      std::optional<Version> expected_rollback_count;
      {
        MapSetLockGuard map_set_guard(*pimpl->store, maps_created);
        c = apply_changes(
          all_changes,
          [&](bool has_new_map) {
            auto resolution =
              pimpl->store->next_version(has_new_map, pimpl->commit_view);
            commit_term_changed = !resolution.has_value();
            if (!resolution.has_value())
            {
              return std::optional<VersionResolution>{};
            }

            const auto
              [resolved_version, previous_last_new_map, rollback_count] =
                resolution.value();
            expected_rollback_count = rollback_count;
            return std::optional<VersionResolution>(
              std::in_place, resolved_version, previous_last_new_map);
          },
          hooks,
          pimpl->created_maps,
          new_maps_conflict_version,
          track_deletes_on_missing_keys);
      }

      success = c.has_value();

      if (!success)
      {
        // This Tx is now in a dead state. Caller should create a new Tx and try
        // again.
        if (commit_term_changed)
        {
          LOG_TRACE_FMT(
            "Could not commit transaction because its commit term changed");
          return CommitResult::FAIL_NO_REPLICATE;
        }

        LOG_TRACE_FMT("Could not commit transaction due to conflict");
        return CommitResult::FAIL_CONFLICT;
      }

      committed = true;
      version = c.value();

      const auto force_ledger_chunk =
        tx_flag_enabled(TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);
      const auto snapshot_at_next_signature =
        tx_flag_enabled(TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);

      if (version == NoVersion)
      {
        // Read-only transaction. It has no version to attach a ledger chunk
        // to, but a requested snapshot must still be armed, as it was before
        // these flags became rollback-sensitive.
        if (snapshot_at_next_signature)
        {
          pimpl->store->set_flag(
            AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
          unset_tx_flag(TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
        }
        return CommitResult::SUCCESS;
      }

      // These side effects outlive this transaction, so they must not be
      // applied if a concurrent rollback has already discarded its writes.
      if (force_ledger_chunk || snapshot_at_next_signature)
      {
        if (!expected_rollback_count.has_value())
        {
          throw std::logic_error(
            "Transaction was allocated a version without a rollback count");
        }

        if (!pimpl->store->apply_tx_flags(
              version,
              pimpl->commit_view,
              expected_rollback_count.value(),
              force_ledger_chunk,
              snapshot_at_next_signature))
        {
          return CommitResult::FAIL_NO_REPLICATE;
        }
      }

      // From here, we have received a unique commit version and made
      // modifications to our local kv. If we fail in any way, we cannot
      // recover.
      try
      {
        ccf::crypto::Sha256Hash commit_evidence_digest;
        std::string commit_evidence;
        auto data = serialise(
          commit_evidence_digest,
          commit_evidence,
          claims,
          pimpl->store->get_max_transaction_size());
        CCF_ASSERT_FMT(
          projected_entry_size.has_value() &&
            data.size() == projected_entry_size.value(),
          "Projected ledger entry size {} does not match serialised size {}",
          projected_entry_size.value_or(0),
          data.size());

        if (write_set_observer != nullptr)
        {
          ccf::crypto::Sha256Hash ws_digest({data.data(), data.size()});
          write_set_observer(ws_digest, commit_evidence);
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

    /** Get version at which this transaction was committed.
     *
     * Throws if this is not successfully committed - should only be called if
     * an earlier call to commit() returned CommitResult::SUCCESS
     *
     * @return Commit version
     */
    [[nodiscard]] Version commit_version() const
    {
      if (!committed)
      {
        throw std::logic_error("Transaction not yet committed");
      }

      if (!success)
      {
        throw std::logic_error("Transaction aborted");
      }

      return version;
    }

    /** Get term in which this transaction was committed.
     *
     * Throws if this is not successfully committed - should only be called if
     * an earlier call to commit() returned CommitResult::SUCCESS
     *
     * @return Commit term
     */
    [[nodiscard]] Version commit_term() const
    {
      if (!committed)
      {
        throw std::logic_error("Transaction not yet committed");
      }

      if (!success)
      {
        throw std::logic_error("Transaction aborted");
      }

      return pimpl->commit_view;
    }

    [[nodiscard]] std::optional<TxID> get_txid() const
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
        return pimpl->read_txid;
      }

      // Write transaction
      return TxID(pimpl->commit_view, version);
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

    void set_root_at_read_version(const ccf::crypto::Sha256Hash& r)
    {
      root_at_read_version = r;
    }

    virtual void set_tx_flag(TxFlag flag)
    {
      flags |= static_cast<TxFlags>(flag);
    }

    virtual void unset_tx_flag(TxFlag flag)
    {
      flags &= ~static_cast<TxFlags>(flag);
    }

    [[nodiscard]] virtual bool tx_flag_enabled(TxFlag f) const
    {
      return (flags & static_cast<TxFlags>(f)) != 0;
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
  private:
    Version rollback_count = 0;

  public:
    ReservedTx(
      AbstractStore* _store,
      Term read_term,
      const TxID& reserved_tx_id,
      Version rollback_count_) :
      CommittableTx(_store),
      rollback_count(rollback_count_)
    {
      version = reserved_tx_id.seqno;
      pimpl->commit_view = reserved_tx_id.view;
      pimpl->read_txid = TxID(read_term, reserved_tx_id.seqno - 1);
    }

    // Used by frontend to commit reserved transactions
    PendingTxInfo commit_reserved()
    {
      if (committed)
      {
        throw std::logic_error("Transaction already committed");
      }

      if (all_changes.empty())
      {
        throw std::logic_error("Reserved transaction cannot be empty");
      }

      std::vector<ConsensusHookPtr> hooks;
      bool track_deletes_on_missing_keys = false;

      // A reserved transaction can create maps too - the first signature
      // creates the signature tables. As in commit(), hold the map set while
      // applying, so that add_dynamic_map() does not mutate it underneath a
      // concurrent reader.
      const bool maps_created = !pimpl->created_maps.empty();

      std::optional<Version> c;
      {
        MapSetLockGuard map_set_guard(*pimpl->store, maps_created);
        c = apply_changes(
          all_changes,
          [this](bool) { return std::make_tuple(version, version - 1); },
          hooks,
          pimpl->created_maps,
          version,
          track_deletes_on_missing_keys,
          rollback_count);
      }

      success = c.has_value();

      if (!success)
      {
        if (pimpl->store->check_rollback_count(rollback_count))
        {
          throw std::logic_error("Failed to commit reserved transaction");
        }

        committed = true;
        return {
          CommitResult::FAIL_NO_REPLICATE, {}, ccf::empty_claims(), {}, {}};
      }

      ccf::crypto::Sha256Hash commit_evidence_digest;
      std::string commit_evidence;

      // This is a signature and, if the ledger chunking or snapshot flags are
      // enabled, we want the host to create a chunk when it sees this entry.
      // Deciding this and recording the chunk must be atomic with respect to
      // rollback, so that a signature a rollback discards leaves no marker
      // behind.
      const auto should_create_chunk = pimpl->store->prepare_reserved_tx(
        version, pimpl->commit_view, rollback_count);
      if (!should_create_chunk.has_value())
      {
        committed = true;
        return {
          CommitResult::FAIL_NO_REPLICATE, {}, ccf::empty_claims(), {}, {}};
      }

      if (should_create_chunk.value())
      {
        entry_flags |= EntryFlags::FORCE_LEDGER_CHUNK_AFTER;
        LOG_DEBUG_FMT(
          "Ending ledger chunk with signature at {}.{}",
          pimpl->commit_view,
          version);
      }

      committed = true;
      auto claims = ccf::empty_claims();
      // Reserved transactions are used solely for signatures. They must always
      // fill their reserved version, so the operator-configured transaction
      // size limit does not apply to them.
      auto data = serialise(
        commit_evidence_digest,
        commit_evidence,
        claims,
        max_serialised_entry_size);

      return {
        CommitResult::SUCCESS,
        std::move(data),
        ccf::empty_claims(),
        std::move(commit_evidence_digest),
        std::move(hooks)};
    }
  };
}
