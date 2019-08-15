// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kvtypes.h"
#include "raft.h"

#include <memory>

namespace raft
{
  template <class LedgerProxy, class ChannelProxy>
  class RaftConsensus : public kv::Consensus
  {
  private:
    std::unique_ptr<Raft<LedgerProxy, ChannelProxy>> raft;

  public:
    RaftConsensus(std::unique_ptr<Raft<LedgerProxy, ChannelProxy>> raft_) :
      Consensus(raft_->id()),
      raft(std::move(raft_))
    {}

    bool is_primary()
    {
      return raft->is_leader();
    }

    bool is_backup()
    {
      return raft->is_follower();
    }

    void force_become_primary()
    {
      raft->force_become_leader();
    }

    void force_become_primary(
      kv::SeqNo seqno,
      kv::View view,
      const std::vector<kv::Version>& terms,
      kv::SeqNo commit_seqno)
    {
      raft->force_become_leader(seqno, view, terms, commit_seqno);
    }

    bool replicate(
      const std::vector<std::tuple<kv::SeqNo, std::vector<uint8_t>, bool>>&
        entries)
    {
      return raft->replicate(entries);
    }

    kv::View get_view()
    {
      return raft->get_term();
    }

    kv::View get_view(kv::SeqNo seqno)
    {
      return raft->get_term(seqno);
    }

    kv::SeqNo get_commit_seqno()
    {
      return raft->get_commit_idx();
    }

    NodeId primary()
    {
      return raft->leader();
    }

    void recv_message(const uint8_t* data, size_t size)
    {
      return raft->recv_message(data, size);
    }

    void add_configuration(
      kv::SeqNo seqno,
      std::unordered_set<NodeId> conf,
      const NodeConf& node_conf = {})
    {
      raft->add_configuration(seqno, conf);
    }

    void periodic(std::chrono::milliseconds elapsed)
    {
      raft->periodic(elapsed);
    }

    void enable_all_domains()
    {
      raft->enable_all_domains();
    }

    void resume_replication()
    {
      raft->resume_replication();
    }

    void suspend_replication(kv::Version version)
    {
      raft->suspend_replication(version);
    }
  };
}