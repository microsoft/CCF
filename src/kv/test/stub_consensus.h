// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/symmetric_key.h"
#include "consensus/aft/impl/state.h"
#include "kv/kv_types.h"
#include "kv/store.h"

#include <algorithm>
#include <iostream>

namespace ccf::kv::test
{
  static NodeId PrimaryNodeId = std::string("PrimaryNodeId");
  static NodeId FirstBackupNodeId = std::string("FirstBackupNodeId");
  static NodeId SecondBackupNodeId = std::string("SecondBackupNodeId");
  static NodeId ThirdBackupNodeId = std::string("ThirdBackupNodeId");
  static NodeId FourthBackupNodeId = std::string("FourthBackupNodeId");

  class StubConsensus : public Consensus
  {
  public:
    std::vector<BatchVector::value_type> replica;
    ccf::TxID committed_txid = {};
    ccf::View current_view = 0;
    ccf::SeqNo last_signature = 0;

    aft::ViewHistory view_history;

    enum State
    {
      Primary,
      Backup,
      Candidate
    };

    State state;
    NodeId local_id;

    StubConsensus() : replica(), state(Backup), local_id(PrimaryNodeId) {}

    virtual NodeId id() override
    {
      return local_id;
    }

    virtual bool is_primary() override
    {
      return state == Primary;
    }

    virtual bool is_candidate() override
    {
      return state == Candidate;
    }

    virtual bool can_replicate() override
    {
      return state == Primary;
    }

    virtual bool is_at_max_capacity() override
    {
      return false;
    }

    virtual Consensus::SignatureDisposition get_signature_disposition() override
    {
      if (state == Primary)
      {
        return Consensus::SignatureDisposition::CAN_SIGN;
      }
      else
      {
        return Consensus::SignatureDisposition::CANT_REPLICATE;
      }
    }

    virtual bool is_backup() override
    {
      return state == Backup;
    }

    virtual void force_become_primary() override
    {
      state = Primary;
    }

    virtual void force_become_primary(
      ccf::SeqNo,
      ccf::View,
      const std::vector<ccf::SeqNo>&,
      ccf::SeqNo) override
    {
      state = Primary;
    }

    virtual void init_as_backup(
      ccf::SeqNo,
      ccf::View,
      const std::vector<ccf::SeqNo>&,
      ccf::SeqNo) override
    {
      state = Backup;
    }

    bool replicate(const BatchVector& entries, ccf::View view) override
    {
      for (const auto& entry : entries)
      {
        replica.push_back(entry);

        const auto& [v, data, committable, hooks] = entry;

        // Simplification: all entries are replicated in the same term
        view_history.update(v, view);

        if (committable)
        {
          // All committable indices are instantly committed
          committed_txid = {view, v};
        }
      }
      current_view = view;
      return true;
    }

    std::optional<std::vector<uint8_t>> get_latest_data()
    {
      if (!replica.empty())
      {
        return *std::get<1>(replica.back());
      }
      else
      {
        return std::nullopt;
      }
    }

    std::optional<BatchVector::value_type> pop_oldest_entry()
    {
      if (!replica.empty())
      {
        auto entry = replica.front();
        replica.erase(replica.begin());
        return entry;
      }
      else
      {
        return std::nullopt;
      }
    }

    size_t number_of_replicas()
    {
      return replica.size();
    }

    void flush()
    {
      replica.clear();
    }

    std::pair<ccf::View, ccf::SeqNo> get_committed_txid() override
    {
      return {committed_txid.view, committed_txid.seqno};
    }

    ccf::SeqNo get_committed_seqno() override
    {
      return committed_txid.seqno;
    }

    std::optional<NodeId> primary() override
    {
      return PrimaryNodeId;
    }

    ccf::View get_view(ccf::SeqNo seqno) override
    {
      return view_history.view_at(seqno);
    }

    ccf::View get_view() override
    {
      return current_view;
    }

    std::vector<ccf::SeqNo> get_view_history(ccf::SeqNo seqno) override
    {
      return view_history.get_history_until(seqno);
    }

    std::vector<ccf::SeqNo> get_view_history_since(ccf::SeqNo seqno) override
    {
      return view_history.get_history_since(seqno);
    }

    void recv_message(
      const NodeId& from, const uint8_t* data, size_t size) override
    {}

    void add_configuration(
      ccf::SeqNo seqno, const Configuration::Nodes& conf) override
    {}

    Configuration::Nodes get_latest_configuration_unsafe() const override
    {
      return {};
    }

    Configuration::Nodes get_latest_configuration() override
    {
      return {};
    }

    ConsensusDetails get_details() override
    {
      return ConsensusDetails{{}, {}, MembershipState::Active};
    }

    void set_last_signature_at(ccf::SeqNo seqno)
    {
      last_signature = seqno;
    }
  };

  class BackupStubConsensus : public StubConsensus
  {
  public:
    BackupStubConsensus() : StubConsensus() {}

    bool is_primary() override
    {
      return false;
    }

    bool replicate(const BatchVector& entries, ccf::View view) override
    {
      return false;
    }

    bool can_replicate() override
    {
      return false;
    }

    Consensus::SignatureDisposition get_signature_disposition() override
    {
      return Consensus::SignatureDisposition::CANT_REPLICATE;
    }
  };

  class PrimaryStubConsensus : public StubConsensus
  {
  public:
    PrimaryStubConsensus() : StubConsensus() {}

    bool is_primary() override
    {
      return true;
    }

    bool can_replicate() override
    {
      return true;
    }

    Consensus::SignatureDisposition get_signature_disposition() override
    {
      return Consensus::SignatureDisposition::CAN_SIGN;
    }
  };

  class RollbackAwarePrimaryStubConsensus
    : public ccf::kv::test::PrimaryStubConsensus
  {
  private:
    ccf::kv::Store& store;
    ccf::SeqNo last_idx = 0;

  public:
    RollbackAwarePrimaryStubConsensus(ccf::kv::Store& store_) : store(store_) {}

    bool replicate(const ccf::kv::BatchVector& entries, ccf::View view) override
    {
      const auto replicated =
        ccf::kv::test::PrimaryStubConsensus::replicate(entries, view);

      if (replicated)
      {
        for (const auto& [version, data, committable, hooks] : entries)
        {
          last_idx = std::max(last_idx, version);
        }
      }

      return replicated;
    }

    ccf::View get_view(ccf::SeqNo seqno) override
    {
      if (seqno > last_idx)
      {
        return ccf::VIEW_UNKNOWN;
      }

      return ccf::kv::test::PrimaryStubConsensus::get_view(seqno);
    }

    ccf::View get_view() override
    {
      return ccf::kv::test::PrimaryStubConsensus::get_view();
    }

    [[nodiscard]] ccf::SeqNo get_last_seqno() const
    {
      return last_idx;
    }

    void rollback(ccf::SeqNo rollback_idx, ccf::View new_view)
    {
      if (rollback_idx > last_idx)
      {
        throw std::logic_error(fmt::format(
          "Cannot rollback stub consensus from {} to {}",
          last_idx,
          rollback_idx));
      }

      const auto retained_term = get_view(rollback_idx);
      if (retained_term == ccf::VIEW_UNKNOWN)
      {
        throw std::logic_error(fmt::format(
          "Cannot determine retained term at {} during rollback",
          rollback_idx));
      }

      if (rollback_idx > replica.size())
      {
        throw std::logic_error(fmt::format(
          "Cannot truncate {} replicated entries to {}",
          replica.size(),
          rollback_idx));
      }

      store.rollback({retained_term, rollback_idx}, new_view);

      // equivalent to ledger->truncate(idx)
      replica.resize(rollback_idx);
      last_idx = rollback_idx;
      view_history.rollback(rollback_idx);
      current_view = new_view;
    }
  };
}
