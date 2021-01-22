// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv_types.h"
#include "node/progress_tracker.h"
#include "node/signatures.h"
#include "tx.h"
#include "view_containers.h"

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
      kv::OrderedChanges& changes,
      kv::MapCollection& new_maps,
      bool ignore_strict_versions = false) = 0;

    virtual DeserialiseSuccess commit_deserialised(
      kv::OrderedChanges& changes,
      kv::Version& v,
      const MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks) = 0;
  };

  class CFTExecutionWrapper : public IExecutionWrapper
  {
  public:
    CFTExecutionWrapper(
      ExecutionWrapperStore* self_,
      std::shared_ptr<TxHistory> history_,
      const std::vector<uint8_t>& data_,
      bool public_only_) :
      self(self_), history(history_), data(data_), public_only(public_only_)
    {}

    DeserialiseSuccess Execute() override
    {
      return fn(self, data, history, public_only, v, &term, changes, new_maps, hooks);
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

    std::function<DeserialiseSuccess(
      ExecutionWrapperStore* self,
      const std::vector<uint8_t>& data,
      std::shared_ptr<TxHistory> history,
      bool public_only,
      kv::Version& v,
      Term* term,
      OrderedChanges& changes,
      MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks)>
      fn = [](
             ExecutionWrapperStore* self,
             const std::vector<uint8_t>& data,
             std::shared_ptr<TxHistory> history,
             bool public_only,
             kv::Version& v,
             Term* term_,
             OrderedChanges& changes,
             MapCollection& new_maps,
             kv::ConsensusHookPtrs& hooks) -> DeserialiseSuccess {
      if (!self->fill_maps(data, public_only, v, changes, new_maps, true))
      {
        return DeserialiseSuccess::FAILED;
      }

      DeserialiseSuccess success =
        self->commit_deserialised(changes, v, new_maps, hooks);
      if (success == DeserialiseSuccess::FAILED)
      {
        return success;
      }

      auto search = changes.find(ccf::Tables::SIGNATURES);
      if (search != changes.end())
      {
        // Transactions containing a signature must only contain
        // a signature and must be verified
        if (changes.size() > 1)
        {
          LOG_FAIL_FMT("Failed to deserialise");
          LOG_DEBUG_FMT("Unexpected contents in signature transaction {}", v);
          return DeserialiseSuccess::FAILED;
        }

        if (history)
        {
          if (!history->verify(term_))
          {
            LOG_FAIL_FMT("Failed to deserialise");
            LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
            return DeserialiseSuccess::FAILED;
          }
        }
        success = DeserialiseSuccess::PASS_SIGNATURE;
      }

      search = changes.find(ccf::Tables::SNAPSHOT_EVIDENCE);
      if (search != changes.end())
      {
        success = DeserialiseSuccess::PASS_SNAPSHOT_EVIDENCE;
      }

      if (history)
      {
        history->append(data);
      }
      return success;
    };

    ExecutionWrapperStore* self;
    std::shared_ptr<TxHistory> history;
    const std::vector<uint8_t> data;
    bool public_only;
    kv::Version v;
    Term term;
    OrderedChanges changes;
    MapCollection new_maps;
    kv::ConsensusHookPtrs hooks;
  };

  class BFTExecutionWrapper : public IExecutionWrapper
  {
  public:
    BFTExecutionWrapper(
      ExecutionWrapperStore* self_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_,
      std::shared_ptr<Consensus> consensus_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      self(self_),
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

    std::function<DeserialiseSuccess(
      ExecutionWrapperStore* self,
      const std::vector<uint8_t>& data,
      bool public_only,
      kv::Version& v,
      Term* term,
      Version* version,
      ccf::PrimarySignature* sig,
      OrderedChanges& changes,
      MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks)>
      fn = nullptr;

    ExecutionWrapperStore* self;
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
  };

  class SignatureBFTExec : public BFTExecutionWrapper
  {
  public:
    SignatureBFTExec(
      ExecutionWrapperStore* self_,
      std::shared_ptr<TxHistory> history_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        self_,
        history_,
        nullptr,
        nullptr,
        data_,
        public_only_,
        v_,
        std::move(changes_),
        std::move(new_maps_))
    {}

    DeserialiseSuccess Execute() override
    {
      return fn(self, data, history, v, &term, &sig, changes, new_maps, hooks);
    }

    std::function<DeserialiseSuccess(
      ExecutionWrapperStore* self,
      const std::vector<uint8_t>& data,
      std::shared_ptr<TxHistory> history,
      kv::Version& v,
      Term* term,
      ccf::PrimarySignature* sig,
      OrderedChanges& changes,
      MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks)>
      fn = [](
             ExecutionWrapperStore* self,
             const std::vector<uint8_t>& data,
             std::shared_ptr<TxHistory> history,
             kv::Version& v,
             Term* term_,
             ccf::PrimarySignature* sig,
             OrderedChanges& changes,
             MapCollection& new_maps,
             kv::ConsensusHookPtrs& hooks) -> DeserialiseSuccess

    {
      DeserialiseSuccess success =
        self->commit_deserialised(changes, v, new_maps, hooks);
      if (success == DeserialiseSuccess::FAILED)
      {
        return success;
      }

      bool result = true;
      if (sig != nullptr)
      {
        auto r = history->verify_and_sign(*sig, term_);
        if (
          r != kv::TxHistory::Result::OK &&
          r != kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK)
        {
          result = false;
        }
      }
      else
      {
        result = history->verify(term_);
      }

      if (!result)
      {
        LOG_FAIL_FMT("Failed to deserialise");
        LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
        throw std::logic_error(
          "Failed to verify signature, view-changes not implemented");
        return DeserialiseSuccess::FAILED;
      }
      history->append(data);
      return DeserialiseSuccess::PASS_SIGNATURE;
    };
  };

  class BackupSignatureBFTExec : public BFTExecutionWrapper
  {
  public:
    BackupSignatureBFTExec(
      ExecutionWrapperStore* self_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_,
      std::shared_ptr<Consensus> consensus_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        self_,
        history_,
        progress_tracker_,
        consensus_,
        data_,
        public_only_,
        v_,
        std::move(changes_),
        std::move(new_maps_))
    {}

    DeserialiseSuccess Execute() override
    {
      return fn(self, data, history, progress_tracker, consensus, v, &term, &version, changes, new_maps, hooks);
    }

    std::function<DeserialiseSuccess(
      ExecutionWrapperStore* self,
      const std::vector<uint8_t>& data,
      std::shared_ptr<TxHistory> history,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker,
      std::shared_ptr<Consensus> consensus,
      kv::Version& v,
      Term* term,
      Version* index,
      OrderedChanges& changes,
      MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks)>
      fn = [](
             ExecutionWrapperStore* self,
             const std::vector<uint8_t>& data,
             std::shared_ptr<TxHistory> history,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker,
      std::shared_ptr<Consensus> consensus,
             kv::Version& v,
             Term* term_,
             Version* index_,
             OrderedChanges& changes,
             MapCollection& new_maps,
             kv::ConsensusHookPtrs& hooks) -> DeserialiseSuccess {
      DeserialiseSuccess success =
        self->commit_deserialised(changes, v, new_maps, hooks);
      if (success == DeserialiseSuccess::FAILED)
      {
        return success;
      }

      kv::TxID tx_id;

      auto r = progress_tracker->receive_backup_signatures(
        tx_id, consensus->node_count(), consensus->is_primary());
      if (r == kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK)
      {
        success = DeserialiseSuccess::PASS_BACKUP_SIGNATURE_SEND_ACK;
      }
      else if (r == kv::TxHistory::Result::OK)
      {
        success = DeserialiseSuccess::PASS_BACKUP_SIGNATURE;
      }
      else
      {
        LOG_FAIL_FMT("receive_backup_signatures Failed");
        LOG_DEBUG_FMT("Signature in transaction {} failed to verify", v);
        throw std::logic_error(
          "Failed to verify signature, view-changes not implemented");
        return DeserialiseSuccess::FAILED;
      }

      *term_ = tx_id.term;
      *index_ = tx_id.version;

      history->append(data);
      return success;
    };
  };

  class NoncesBFTExec : public BFTExecutionWrapper
  {
  public:
    NoncesBFTExec(
      ExecutionWrapperStore* self_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        self_,
        history_,
        progress_tracker_,
        nullptr,
        data_,
        public_only_,
        v_,
        std::move(changes_),
        std::move(new_maps_))
    {}

    DeserialiseSuccess Execute() override
    {
      return fn(self, data, history, progress_tracker, v, changes, new_maps, hooks);
    }

    std::function<DeserialiseSuccess(
      ExecutionWrapperStore* self,
      const std::vector<uint8_t>& data,
      std::shared_ptr<TxHistory> history,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker,
      kv::Version& v,
      OrderedChanges& changes,
      MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks)>
      fn = [](
             ExecutionWrapperStore* self,
             const std::vector<uint8_t>& data,
             std::shared_ptr<TxHistory> history,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker,
             kv::Version& v,
             OrderedChanges& changes,
             MapCollection& new_maps,
             kv::ConsensusHookPtrs& hooks) -> DeserialiseSuccess {
      DeserialiseSuccess success =
        self->commit_deserialised(changes, v, new_maps, hooks);
      if (success == DeserialiseSuccess::FAILED)
      {
        return success;
      }

      auto r = progress_tracker->receive_nonces();
      if (r != kv::TxHistory::Result::OK)
      {
        LOG_FAIL_FMT("receive_nonces Failed");
        throw std::logic_error(
          "Failed to verify nonces, view-changes not implemented");
        return DeserialiseSuccess::FAILED;
      }

      history->append(data);
      return DeserialiseSuccess::PASS_NONCES;
    };
  };

  class NewViewBFTExec : public BFTExecutionWrapper
  {
  public:
    NewViewBFTExec(
      ExecutionWrapperStore* self_,
      std::shared_ptr<TxHistory> history_,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker_,
      std::shared_ptr<Consensus> consensus_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      kv::Version v_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        self_,
        history_,
        progress_tracker_,
        consensus_,
        data_,
        public_only_,
        v_,
        std::move(changes_),
        std::move(new_maps_))
    {}

    DeserialiseSuccess Execute() override
    {
      return fn(self, data, history, progress_tracker, consensus, v, &term, &version, changes, new_maps, hooks);
    }

    std::function<DeserialiseSuccess(
      ExecutionWrapperStore* self,
      const std::vector<uint8_t>& data,
      std::shared_ptr<TxHistory> history,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker,
      std::shared_ptr<Consensus> consensus,
      kv::Version& v,
      Term* term,
      Version* index,
      OrderedChanges& changes,
      MapCollection& new_maps,
      kv::ConsensusHookPtrs& hooks)>
      fn = [](
             ExecutionWrapperStore* self,
             const std::vector<uint8_t>& data,
             std::shared_ptr<TxHistory> history,
      std::shared_ptr<ccf::ProgressTracker> progress_tracker,
      std::shared_ptr<Consensus> consensus,
             kv::Version& v,
             Term* term_,
             Version* index_,
             OrderedChanges& changes,
             MapCollection& new_maps,
             kv::ConsensusHookPtrs& hooks) -> DeserialiseSuccess {
      LOG_INFO_FMT("Applying new view");
      DeserialiseSuccess success =
        self->commit_deserialised(changes, v, new_maps, hooks);
      if (success == DeserialiseSuccess::FAILED)
      {
        return success;
      }

      if (!progress_tracker->apply_new_view(
            consensus->primary(),
            consensus->node_count(),
            *term_,
            *index_))
      {
        LOG_FAIL_FMT("apply_new_view Failed");
        LOG_DEBUG_FMT("NewView in transaction {} failed to verify", v);
        return DeserialiseSuccess::FAILED;
      }

      history->append(data);
      return DeserialiseSuccess::PASS_NEW_VIEW;
    };
  };

  class TxBFTExec : public BFTExecutionWrapper
  {
  public:
    TxBFTExec(
      ExecutionWrapperStore* self_,
      std::shared_ptr<TxHistory> history_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      std::unique_ptr<Tx> tx_,
      kv::Version v_,
      OrderedChanges&& changes_,
      MapCollection&& new_maps_) :
      BFTExecutionWrapper(
        self_,
        history_,
        nullptr,
        nullptr,
        data_,
        public_only_,
        v_,
        std::move(changes_),
        std::move(new_maps_))
    {
      tx = std::move(tx_);
    }

    DeserialiseSuccess Execute() override
    {
      return fn(tx, term, changes);
    }

    std::function<DeserialiseSuccess(
      std::unique_ptr<Tx>& tx, Term term, OrderedChanges& changes)>
      fn = [](std::unique_ptr<Tx>& tx, Term term, OrderedChanges& changes)
      -> DeserialiseSuccess {
      tx->set_change_list(std::move(changes), term);
      return DeserialiseSuccess::PASS;
    };
  };
}