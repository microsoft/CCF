// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/symmetric_key.h"
#include "consensus/aft/impl/state.h"
#include "kv/kv_types.h"
#include "service/tables/resharing_types.h"

#include <algorithm>
#include <iostream>

namespace kv::test
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
    ConsensusType consensus_type;
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

    StubConsensus(ConsensusType consensus_type_ = ConsensusType::CFT) :
      replica(),
      consensus_type(consensus_type_),
      state(Backup),
      local_id(PrimaryNodeId)
    {}

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

    ccf::SeqNo get_previous_committable_seqno() override
    {
      // Since we commit instantly in this stub, we do not distinguish
      // committable from committed. The last committable thing we saw was
      // immediately committed, and we store it in committed_txid.
      return committed_txid.seqno;
    }

    ccf::SeqNo get_committed_seqno() override
    {
      return committed_txid.seqno;
    }

    std::optional<NodeId> primary() override
    {
      return PrimaryNodeId;
    }

    bool view_change_in_progress() override
    {
      return false;
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
      ccf::SeqNo seqno,
      const Configuration::Nodes& conf,
      const std::unordered_set<NodeId>& learners = {},
      const std::unordered_set<NodeId>& retired_nodes = {}) override
    {}

    virtual std::optional<kv::Configuration::Nodes> orc(
      kv::ReconfigurationId rid, const NodeId& node_id) override
    {
      return std::nullopt;
    }

    Configuration::Nodes get_latest_configuration_unsafe() const override
    {
      return {};
    }

    Configuration::Nodes get_latest_configuration() override
    {
      return {};
    }

    virtual void update_parameters(kv::ConsensusParameters& params) override {}

    ConsensusDetails get_details() override
    {
      return ConsensusDetails{{}, {}, MembershipState::Active};
    }

    void add_resharing_result(
      ccf::SeqNo seqno,
      ReconfigurationId rid,
      const ccf::ResharingResult& result) override
    {}

    ConsensusType type() override
    {
      return consensus_type;
    }

    void set_last_signature_at(ccf::SeqNo seqno)
    {
      last_signature = seqno;
    }
  };

  class BackupStubConsensus : public StubConsensus
  {
  public:
    BackupStubConsensus(ConsensusType consensus_type = ConsensusType::CFT) :
      StubConsensus(consensus_type)
    {}

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
    PrimaryStubConsensus(ConsensusType consensus_type = ConsensusType::CFT) :
      StubConsensus(consensus_type)
    {}

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
}
