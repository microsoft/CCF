// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "kv/kv_types.h"

#include <algorithm>
#include <iostream>

namespace kv
{
  class StubConsensus : public Consensus
  {
  private:
    std::vector<std::shared_ptr<std::vector<uint8_t>>> replica;
    ConsensusType consensus_type;

  public:
    StubConsensus(ConsensusType consensus_type_ = ConsensusType::RAFT) :
      Consensus(0),
      replica(),
      consensus_type(consensus_type_)
    {}

    bool replicate(const BatchVector& entries) override
    {
      for (auto&& [index, data, globally_committable] : entries)
      {
        replica.push_back(data);
      }
      return true;
    }

    std::pair<std::vector<uint8_t>, bool> get_latest_data()
    {
      if (!replica.empty())
        return std::make_pair(*replica.back(), true);
      else
        return std::make_pair(std::vector<uint8_t>(), false);
    }

    std::pair<std::vector<uint8_t>, bool> pop_oldest_data()
    {
      if (!replica.empty())
      {
        auto pair = std::make_pair(*replica.front(), true);
        replica.erase(replica.begin());
        return pair;
      }
      else
      {
        return std::make_pair(std::vector<uint8_t>(), false);
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

    View get_view() override
    {
      return 0;
    }

    SeqNo get_commit_seqno() override
    {
      return 0;
    }

    NodeId primary() override
    {
      return 1;
    }

    NodeId id() override
    {
      return 0;
    }

    View get_view(SeqNo seqno) override
    {
      return 2;
    }

    void recv_message(OArray&& oa) override {}

    void add_configuration(
      SeqNo seqno,
      std::unordered_set<NodeId> conf,
      const NodeConf& node_conf) override
    {}

    void set_f(ccf::NodeId) override
    {
      return;
    }

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
    BackupStubConsensus(ConsensusType consensus_type = ConsensusType::RAFT) :
      StubConsensus(consensus_type)
    {}

    bool is_primary() override
    {
      return false;
    }

    bool replicate(const BatchVector& entries) override
    {
      return false;
    }
  };

  class PrimaryStubConsensus : public StubConsensus
  {
  public:
    PrimaryStubConsensus(ConsensusType consensus_type = ConsensusType::RAFT) :
      StubConsensus(consensus_type)
    {}

    bool is_primary() override
    {
      return true;
    }
  };
}
