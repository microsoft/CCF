// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apply_changes.h"
#include "consensus/aft/request.h"
#include "kv_types.h"
#include "node/progress_tracker.h"
#include "node/signatures.h"
#include "tx.h"

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
      kv::OrderedChanges& changes,
      kv::MapCollection& new_maps,
      bool ignore_strict_versions = false) = 0;

    virtual bool commit_deserialised(
      kv::OrderedChanges& changes,
      kv::Version& v,
      const MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks) = 0;
  };

  class CFTExecutionWrapper : public AbstractExecutionWrapper
  {
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
      if (!store->fill_maps(
            data,
            public_only,
            v,
            max_conflict_version,
            changes,
            new_maps,
            true))
      {
        return ApplyResult::FAIL;
      }

      if (!store->commit_deserialised(changes, v, new_maps, hooks))
      {
        return ApplyResult::FAIL;
      }
      auto success = ApplyResult::PASS;

      auto search = changes.find(ccf::Tables::SIGNATURES);
      if (search != changes.end())
      {
        // Transactions containing a signature must only contain
        // a signature and must be verified
        if (changes.size() > 1)
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
    kv::Tx& get_tx() override
    {
      throw std::logic_error("get_tx not implemented");
    }

    aft::Request& get_request() override
    {
      throw std::logic_error("get_request not implemented");
    }

    bool support_async_execution() override
    {
      return false;
    }

    virtual uint64_t get_max_conflict_version() override
    {
      return v - 1;
    }

    ExecutionWrapperStore* store;
    std::shared_ptr<TxHistory> history;
    const std::vector<uint8_t> data;
    bool public_only;
    kv::Version v;
    Term term;
    OrderedChanges changes;
    MapCollection new_maps;
    kv::ConsensusHookPtrs hooks;
  };

  class BFTExecutionWrapper : public AbstractExecutionWrapper
  {
  public:
    BFTExecutionWrapper(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_,
      std::shared_ptr<Consensus> consensus_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      store(store_),
      history(history_),
      progress_tracker(progress_tracker_),
      consensus(consensus_),
      data(data_),
      public_only(public_only_),
      v(v_),
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

    Tx& get_tx() override
    {
      return *tx;
    }

    aft::Request& get_request() override
    {
      return req;
    }

    virtual bool support_async_execution() override
    {
      return false;
    }

    virtual uint64_t get_max_conflict_version() override
    {
      return v - 1;
    }

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
    std::unique_ptr<Tx> tx;
    aft::Request req;
  };

  class SignatureBFTExec : public BFTExecutionWrapper
  {
  public:
    SignatureBFTExec(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
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
        std::move(changes_),
        std::move(new_maps_))
    {}

    ApplyResult apply() override
    {
      if (!store->commit_deserialised(changes, v, new_maps, hooks))
      {
        return ApplyResult::FAIL;
      }

      bool result = true;
      auto r = history->verify_and_sign(sig, &term);
      if (
        r != kv::TxHistory::Result::OK &&
        r != kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK)
      {
        result = false;
      }

      if (!result)
      {
        LOG_FAIL_FMT("Failed to deserialise");
        LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
        throw std::logic_error(
          "Failed to verify signature, view-changes not implemented");
        return ApplyResult::FAIL;
      }
      history->append(data);
      return ApplyResult::PASS_SIGNATURE;
    }
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
        std::move(changes_),
        std::move(new_maps_))
    {}

    ApplyResult apply() override
    {
      if (!store->commit_deserialised(changes, v, new_maps, hooks))
      {
        return ApplyResult::FAIL;
      }

      kv::TxID tx_id;
      auto success = ApplyResult::PASS;

      auto r = progress_tracker->receive_backup_signatures(
        tx_id, consensus->node_count(), consensus->is_primary());
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
        LOG_FAIL_FMT("receive_backup_signatures Failed");
        LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
        throw std::logic_error(
          "Failed to verify signature, view-changes not implemented");
        return ApplyResult::FAIL;
      }

      term = tx_id.term;
      version = tx_id.version;

      history->append(data);
      return success;
    }
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
        std::move(changes_),
        std::move(new_maps_))
    {}

    ApplyResult apply() override
    {
      if (!store->commit_deserialised(changes, v, new_maps, hooks))
      {
        LOG_FAIL_FMT("receive_nonces commit_deserialized Failed");
        return ApplyResult::FAIL;
      }

      auto r = progress_tracker->receive_nonces();
      if (r != kv::TxHistory::Result::OK)
      {
        LOG_FAIL_FMT("receive_nonces Failed");
        throw std::logic_error(
          "Failed to verify nonces, view-changes not implemented");
        return ApplyResult::FAIL;
      }

      history->append(data);
      return ApplyResult::PASS_NONCES;
    }
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
        std::move(changes_),
        std::move(new_maps_))
    {}

    ApplyResult apply() override
    {
      LOG_INFO_FMT("Applying new view");
      if (!store->commit_deserialised(changes, v, new_maps, hooks))
      {
        return ApplyResult::FAIL;
      }

      if (!progress_tracker->apply_new_view(
            consensus->primary(), consensus->node_count(), term, version))
      {
        LOG_FAIL_FMT("apply_new_view Failed");
        LOG_DEBUG_FMT("NewView in transaction {} failed to verify", v);
        return ApplyResult::FAIL;
      }

      history->append(data);
      return ApplyResult::PASS_NEW_VIEW;
    }
  };

  class TxBFTExec : public BFTExecutionWrapper
  {
  public:
    TxBFTExec(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      std::unique_ptr<Tx> tx_,
      kv::Version v_,
      kv::Version max_conflict_version_,
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
        std::move(changes_),
        std::move(new_maps_)),
      max_conflict_version(max_conflict_version_)
    {
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

    virtual bool support_async_execution() override
    {
      return true;
    }

    virtual uint64_t get_max_conflict_version() override
    {
      return max_conflict_version;
    }

  private:
    uint64_t max_conflict_version;
  };
}