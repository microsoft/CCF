// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmkey.h"
#include "kv/kvtypes.h"

#include <algorithm>
#include <iostream>

namespace kv
{
  class StubConsensus : public Consensus
  {
  private:
    std::vector<std::vector<uint8_t>> replica;

  public:
    StubConsensus() : replica() {}

    bool replicate(
      const std::vector<std::tuple<kv::SeqNo, std::vector<uint8_t>, bool>>&
        entries) override
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
        return std::make_pair(replica.back(), true);
      else
        return std::make_pair(std::vector<uint8_t>(), false);
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

    NodeId leader() override
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

    bool is_leader() override
    {
      return true;
    }

    bool on_request(const kv::TxHistory::RequestCallbackArgs& args) override
    {
      return true;
    }

    void periodic(std::chrono::milliseconds elapsed) override {}

    bool is_follower() override
    {
      return false;
    }
    void recv_message(const uint8_t* data, size_t size) override {}

    void add_configuration(
      SeqNo seqno,
      std::unordered_set<NodeId> conf,
      const NodeConf& node_conf) override
    {}

    void force_become_leader() override {}

    void force_become_leader(
      SeqNo seqno,
      View view,
      const std::vector<kv::Version>& terms,
      SeqNo commit_seqno_) override
    {}

    void enable_all_domains() override {}

    void resume_replication() override {}

    void suspend_replication(kv::Version) override {}
  };

  class FollowerStubConsensus : public StubConsensus
  {
  public:
    bool is_leader() override
    {
      return false;
    }
  };

  class LeaderStubConsensus : public StubConsensus
  {
  public:
    bool is_leader() override
    {
      return true;
    }
  };
}
