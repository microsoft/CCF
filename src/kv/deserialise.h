// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apply_changes.h"
#include "consensus/aft/request.h"
#include "kv/committable_tx.h"
#include "kv_types.h"
#include "node/progress_tracker.h"
#include "node/signatures.h"

#include <vector>

namespace kv
{
  class ExecutionWrapperStore
  {
  public:
    virtual bool fill_maps(
      const std::vector<uint8_t>& data,
      bool public_only,
      kv::Version& v,
      kv::Version& max_conflict_version,
      kv::Term& view,
      kv::OrderedChanges& changes,
      kv::MapCollection& new_maps,
      bool ignore_strict_versions = false) = 0;

    virtual bool commit_deserialised(
      kv::OrderedChanges& changes,
      kv::Version v,
      kv::Term term,
      const MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks) = 0;
  };

  class CFTExecutionWrapper : public AbstractExecutionWrapper
  {
  private:
    ExecutionWrapperStore* store;
    std::shared_ptr<TxHistory> history;
    const std::vector<uint8_t> data;
    bool public_only;
    kv::Version v;
    Term term;
    OrderedChanges changes;
    MapCollection new_maps;
    kv::ConsensusHookPtrs hooks;

  public:
    CFTExecutionWrapper(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      const std::vector<uint8_t>& data_,
      bool public_only_) :
      store(store_),
      history(history_),
      data(data_),
      public_only(public_only_)
    {}

    ApplyResult apply() override
    {
      kv::Version max_conflict_version;
      kv::Term view;
      if (!store->fill_maps(
            data,
            public_only,
            v,
            max_conflict_version,
            view,
            changes,
            new_maps,
            true))
      {
        return ApplyResult::FAIL;
      }

      if (!store->commit_deserialised(changes, v, view, new_maps, hooks))
      {
        return ApplyResult::FAIL;
      }
      auto success = ApplyResult::PASS;

      auto search = changes.find(ccf::Tables::SIGNATURES);
      if (search != changes.end())
      {
        // Transactions containing a signature must only contain the signature
        // and the serialised Merkle tree and must be verified
        if (
          changes.size() > 2 ||
          changes.find(ccf::Tables::SERIALISED_MERKLE_TREE) == changes.end())
        {
          LOG_FAIL_FMT("Failed to deserialise");
          LOG_DEBUG_FMT("Unexpected contents in signature transaction {}", v);
          return ApplyResult::FAIL;
        }

        if (history)
        {
          if (!history->verify(&term))
          {
            LOG_FAIL_FMT("Failed to deserialise");
            LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
            return ApplyResult::FAIL;
          }
        }
        success = ApplyResult::PASS_SIGNATURE;
      }

      search = changes.find(ccf::Tables::SNAPSHOT_EVIDENCE);
      if (search != changes.end())
      {
        success = ApplyResult::PASS_SNAPSHOT_EVIDENCE;
      }

      search = changes.find(ccf::Tables::ENCRYPTED_PAST_LEDGER_SECRET);
      if (search != changes.end())
      {
        success = ApplyResult::PASS_ENCRYPTED_PAST_LEDGER_SECRET;
      }

      if (history)
      {
        history->append(data);
      }
      return success;
    }

    kv::ConsensusHookPtrs& get_hooks() override
    {
      return hooks;
    }

    const std::vector<uint8_t>& get_entry() override
    {
      return data;
    }

    Term get_term() override
    {
      return term;
    }

    kv::Version get_index() override
    {
      throw std::logic_error("get_index not implemented");
    }
    ccf::PrimarySignature& get_signature() override
    {
      throw std::logic_error("get_signature not implemented");
    }

    aft::Request& get_request() override
    {
      throw std::logic_error("get_request not implemented");
    }

    kv::Version get_max_conflict_version() override
    {
      return v - 1;
    }

    bool support_async_execution() override
    {
      return false;
    }

    bool is_public_only() override
    {
      return public_only;
    }

    bool should_rollback_to_last_committed() override
    {
      return false;
    }
  };

  class BFTExecutionWrapper : public AbstractExecutionWrapper
  {
  protected:
    ExecutionWrapperStore* store;
    std::shared_ptr<TxHistory> history;
    std::shared_ptr<ccf::ProgressTracker> progress_tracker;
    std::shared_ptr<Consensus> consensus;
    const std::vector<uint8_t> data;
    bool public_only;
    kv::Version v;
    Term term;
    Version version;
    ccf::PrimarySignature sig;
    OrderedChanges changes;
    MapCollection new_maps;
    kv::ConsensusHookPtrs hooks;
    aft::Request req;

  public:
    BFTExecutionWrapper(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_,
      std::shared_ptr<Consensus> consensus_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      ccf::View view_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      store(store_),
      history(history_),
      progress_tracker(progress_tracker_),
      consensus(consensus_),
      data(data_),
      public_only(public_only_),
      v(v_),
      term(view_),
      changes(std::move(changes_)),
      new_maps(std::move(new_maps_))
    {}

    kv::ConsensusHookPtrs& get_hooks() override
    {
      return hooks;
    }

    const std::vector<uint8_t>& get_entry() override
    {
      return data;
    }

    Term get_term() override
    {
      return term;
    }

    kv::Version get_index() override
    {
      return version;
    }

    ccf::PrimarySignature& get_signature() override
    {
      return sig;
    }

    aft::Request& get_request() override
    {
      return req;
    }

    kv::Version get_max_conflict_version() override
    {
      return v - 1;
    }

    virtual bool support_async_execution() override
    {
      return false;
    }

    virtual bool is_public_only() override
    {
      return public_only;
    }
  };

  class SignatureBFTExec : public BFTExecutionWrapper
  {
  public:
    SignatureBFTExec(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<Consensus> consensus_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      ccf::View view_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        store_,
        history_,
        nullptr,
        consensus_,
        data_,
        public_only_,
        v_,
        view_,
        std::move(changes_),
        std::move(new_maps_))
    {}

    ApplyResult apply() override
    {
      if (!store->commit_deserialised(changes, v, term, new_maps, hooks))
      {
        return ApplyResult::FAIL;
      }

      auto config = consensus->get_latest_configuration_unsafe();
      bool result = true;
      auto r = history->verify_and_sign(sig, &term, config);
      if (
        r != kv::TxHistory::Result::OK &&
        r != kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK)
      {
        result = false;
        rollback_to_last_committed = true;
      }

      if (!result)
      {
        LOG_FAIL_FMT("Failed to deserialise");
        LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
        return ApplyResult::FAIL;
      }
      history->append(data);
      return ApplyResult::PASS_SIGNATURE;
    }

    bool should_rollback_to_last_committed() override
    {
      return rollback_to_last_committed;
    }

  private:
    bool rollback_to_last_committed = false;
  };

  class BackupSignatureBFTExec : public BFTExecutionWrapper
  {
  public:
    BackupSignatureBFTExec(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_,
      std::shared_ptr<Consensus> consensus_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      ccf::View view_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        store_,
        history_,
        progress_tracker_,
        consensus_,
        data_,
        public_only_,
        v_,
        view_,
        std::move(changes_),
        std::move(new_maps_))
    {}

    ApplyResult apply() override
    {
      if (!store->commit_deserialised(changes, v, term, new_maps, hooks))
      {
        return ApplyResult::FAIL;
      }

      ccf::TxID tx_id;
      auto success = ApplyResult::PASS;
      auto config = consensus->get_latest_configuration_unsafe();
      auto r = progress_tracker->receive_backup_signatures(
        tx_id, config, consensus->is_primary());
      if (r == kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK)
      {
        success = ApplyResult::PASS_BACKUP_SIGNATURE_SEND_ACK;
      }
      else if (r == kv::TxHistory::Result::OK)
      {
        success = ApplyResult::PASS_BACKUP_SIGNATURE;
      }
      else
      {
        rollback_to_last_committed = true;
        LOG_FAIL_FMT("receive_backup_signatures Failed");
        LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
        return ApplyResult::FAIL;
      }

      term = tx_id.view;
      version = tx_id.seqno;

      history->append(data);
      return success;
    }

    bool should_rollback_to_last_committed() override
    {
      return rollback_to_last_committed;
    }

  private:
    bool rollback_to_last_committed = false;
  };

  class NoncesBFTExec : public BFTExecutionWrapper
  {
  public:
    NoncesBFTExec(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      ccf::View view_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        store_,
        history_,
        progress_tracker_,
        nullptr,
        data_,
        public_only_,
        v_,
        view_,
        std::move(changes_),
        std::move(new_maps_))
    {}

    ApplyResult apply() override
    {
      if (!store->commit_deserialised(changes, v, term, new_maps, hooks))
      {
        LOG_FAIL_FMT("receive_nonces commit_deserialised Failed");
        return ApplyResult::FAIL;
      }

      auto r = progress_tracker->receive_nonces();
      if (r != kv::TxHistory::Result::OK)
      {
        LOG_FAIL_FMT("receive_nonces Failed");
        rollback_to_last_committed = true;
        return ApplyResult::FAIL;
      }

      history->append(data);
      return ApplyResult::PASS_NONCES;
    }

    bool should_rollback_to_last_committed() override
    {
      return rollback_to_last_committed;
    }

  private:
    bool rollback_to_last_committed = false;
  };

  class NewViewBFTExec : public BFTExecutionWrapper
  {
  public:
    NewViewBFTExec(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_,
      std::shared_ptr<Consensus> consensus_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      ccf::View view_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        store_,
        history_,
        progress_tracker_,
        consensus_,
        data_,
        public_only_,
        v_,
        view_,
        std::move(changes_),
        std::move(new_maps_))
    {}

    ApplyResult apply() override
    {
      LOG_INFO_FMT("Applying new view");
      if (!store->commit_deserialised(changes, v, term, new_maps, hooks))
      {
        return ApplyResult::FAIL;
      }

      auto config = consensus->get_latest_configuration_unsafe();
      if (!progress_tracker->apply_new_view(config, term))
      {
        rollback_to_last_committed = true;
        LOG_FAIL_FMT("apply_new_view Failed");
        LOG_DEBUG_FMT("NewView in transaction {} failed to verify", v);
        return ApplyResult::FAIL;
      }

      history->append(data);
      return ApplyResult::PASS_NEW_VIEW;
    }

    bool should_rollback_to_last_committed() override
    {
      return rollback_to_last_committed;
    }

  private:
    bool rollback_to_last_committed = false;
  };

  class TxBFTExec : public BFTExecutionWrapper
  {
  private:
    uint64_t max_conflict_version;
    std::unique_ptr<CommittableTx> tx;

  public:
    TxBFTExec(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      std::unique_ptr<CommittableTx> tx_,
      kv::Version v_,
      kv::Version max_conflict_version_,
      ccf::View view_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        store_,
        history_,
        nullptr,
        nullptr,
        data_,
        public_only_,
        v_,
        view_,
        std::move(changes_),
        std::move(new_maps_)),
      max_conflict_version(max_conflict_version_)
    {
      max_conflict_version = max_conflict_version_;
      tx = std::move(tx_);
    }

    ApplyResult apply() override
    {
      tx->set_change_list(std::move(changes), term);

      auto aft_requests = tx->rw<aft::RequestsMap>(ccf::Tables::AFT_REQUESTS);
      auto req_v = aft_requests->get(0);
      CCF_ASSERT(
        req_v.has_value(),
        "Deserialised append entry, but requests map is empty");
      req = req_v.value();

      return ApplyResult::PASS;
    }

    kv::Version get_max_conflict_version() override
    {
      return max_conflict_version;
    }

    bool support_async_execution() override
    {
      return true;
    }

    bool should_rollback_to_last_committed() override
    {
      return false;
    }
  };

  class TxBFTApply : public BFTExecutionWrapper
  {
  private:
    uint64_t max_conflict_version;
    std::unique_ptr<CommittableTx> tx;

  public:
    TxBFTApply(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      std::unique_ptr<CommittableTx> tx_,
      kv::Version v_,
      kv::Version max_conflict_version_,
      ccf::View view_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        store_,
        history_,
        nullptr,
        nullptr,
        data_,
        public_only_,
        v_,
        view_,
        std::move(changes_),
        std::move(new_maps_)),
      max_conflict_version(max_conflict_version_)
    {
      max_conflict_version = max_conflict_version_;
      tx = std::move(tx_);
    }

    ApplyResult apply() override
    {
      if (!store->commit_deserialised(changes, v, term, new_maps, hooks))
      {
        return ApplyResult::FAIL;
      }

      if (history)
      {
        history->append(data);
      }

      if (!public_only)
      {
        tx->set_change_list(std::move(changes), term);

        auto aft_requests = tx->rw<aft::RequestsMap>(ccf::Tables::AFT_REQUESTS);
        auto req_v = aft_requests->get(0);
        CCF_ASSERT(
          req_v.has_value(),
          "Deserialised append entry, but requests map is empty");
        req = req_v.value();
      }

      return ApplyResult::PASS_APPLY;
    }

    kv::Version get_max_conflict_version() override
    {
      return max_conflict_version;
    }

    bool support_async_execution() override
    {
      return false;
    }

    bool should_rollback_to_last_committed() override
    {
      return false;
    }
  };
}