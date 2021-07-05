// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/impl/state.h"
#include "crypto/symmetric_key.h"
#include "kv/kv_types.h"

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
  private:
    std::vector<BatchVector::value_type> replica;
    ConsensusType consensus_type;

  public:
    aft::ViewHistory view_history;

    StubConsensus(ConsensusType consensus_type_ = ConsensusType::CFT) :
      Consensus(PrimaryNodeId),
      replica(),
      consensus_type(consensus_type_)
    {}

    bool replicate(const BatchVector& entries, ccf::View view) override
    {
      for (const auto& entry : entries)
      {
        replica.push_back(entry);

        // Simplification: all entries are replicated in the same term
        view_history.update(std::get<0>(entry), 2);
      }
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
      return {2, 0};
    }

    std::optional<SignableTxIndices> get_signable_txid() override
    {
      auto txid = get_committed_txid();
      SignableTxIndices r;
      r.term = txid.first;
      r.version = txid.second;
      r.previous_version = 0;
      return r;
    }

    ccf::SeqNo get_committed_seqno() override
    {
      return 0;
    }

    std::optional<NodeId> primary() override
    {
      return PrimaryNodeId;
    }

    bool view_change_in_progress() override
    {
      return false;
    }

    std::set<NodeId> active_nodes() override
    {
      return {PrimaryNodeId};
    }

    NodeId id() override
    {
      return PrimaryNodeId;
    }

    ccf::View get_view(ccf::SeqNo seqno) override
    {
      return 2;
    }

    ccf::View get_view() override
    {
      return 2;
    }

    std::vector<ccf::SeqNo> get_view_history(ccf::SeqNo seqno) override
    {
      return view_history.get_history_until(seqno);
    }

    void initialise_view_history(
      const std::vector<ccf::SeqNo>& view_history_) override
    {
      view_history.initialise(view_history_);
    }

    void recv_message(
      const NodeId& from, const uint8_t* data, size_t size) override
    {}

    void add_configuration(
      ccf::SeqNo seqno,
      const Configuration::Nodes& conf,
      const std::unordered_set<NodeId>& learners = {}) override
    {}

    void add_network_configuration(
      ccf::SeqNo seqno, const NetworkConfiguration& config) override
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
      return ConsensusDetails{{}, {}, ReplicaState::Candidate};
    }

    void add_identity(
      ccf::SeqNo seqno,
      kv::ReconfigurationId rid,
      const ccf::Identity& identity) override
    {}

    void emit_signature() override
    {
      return;
    }

    ConsensusType type() override
    {
      return consensus_type;
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
  };
}
