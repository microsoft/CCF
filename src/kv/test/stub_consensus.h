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

    explicit StubConsensus(State state_ = Primary) :
      replica(),
      state(state_),
      local_id(PrimaryNodeId)
    {}

    virtual NodeId id()
    {
      return local_id;
    }

    virtual bool is_primary()
    {
      return state == Primary;
    }

    virtual bool is_candidate()
    {
      return state == Candidate;
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

    virtual bool is_backup()
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
      if (state != Primary)
      {
        return false;
      }

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

    virtual std::pair<ccf::View, ccf::SeqNo> get_committed_txid()
    {
      return {committed_txid.view, committed_txid.seqno};
    }

    virtual ccf::SeqNo get_committed_seqno()
    {
      return committed_txid.seqno;
    }

    virtual std::optional<NodeId> primary()
    {
      return PrimaryNodeId;
    }

    virtual ccf::View get_view()
    {
      return current_view;
    }

    ccf::TxStatus evaluate_tx_status(
      ccf::View target_view, ccf::SeqNo target_seqno) override
    {
      return ccf::evaluate_tx_status(
        target_view,
        target_seqno,
        view_history.view_at(target_seqno),
        committed_txid.view,
        committed_txid.seqno);
    }

    void recv_message(
      const NodeId& from, const uint8_t* data, size_t size) override
    {}

    void add_configuration(
      ccf::SeqNo seqno, const Configuration::Nodes& configuration) override
    {}

    void update_configuration(
      ccf::SeqNo seqno, const Configuration::NodeChanges& changes) override
    {}

    virtual Configuration::Nodes get_latest_configuration()
    {
      return {};
    }

    ConsensusLightDetails get_light_details() override
    {
      ConsensusLightDetails details;
      details.membership_state = MembershipState::Active;
      details.leadership_state = state == Primary ? LeadershipState::Leader :
        state == Candidate                        ? LeadershipState::Candidate :
                                                    LeadershipState::Follower;
      details.primary_id = PrimaryNodeId;
      details.current_view = current_view;
      details.committed_view = committed_txid.view;
      details.committed_seqno = committed_txid.seqno;
      return details;
    }

    ConsensusDetails get_details() override
    {
      ConsensusDetails details;
      static_cast<ConsensusLightDetails&>(details) = get_light_details();
      details.view_history.starts = view_history.get_history_until();
      return details;
    }

    void set_last_signature_at(ccf::SeqNo seqno)
    {
      last_signature = seqno;
    }
  };

  class BackupStubConsensus : public StubConsensus
  {
  public:
    BackupStubConsensus() : StubConsensus(Backup) {}
  };

  class PrimaryStubConsensus : public StubConsensus
  {
  public:
    PrimaryStubConsensus() : StubConsensus(Primary) {}
  };
}
