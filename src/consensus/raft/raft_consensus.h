// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "raft.h"

#include <memory>

namespace raft
{
  // This class acts as an adapter between the generic Consensus API and
  // the Raft API, allowing for a mapping between the generic consensus
  // terminology and the terminology that is specific to Raft

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

    bool is_primary() override
    {
      return raft->is_leader();
    }

    bool is_backup() override
    {
      return raft->is_follower();
    }

    void force_become_primary() override
    {
      raft->force_become_leader();
    }

    void force_become_primary(
      SeqNo seqno,
      View view,
      const std::vector<kv::Version>& terms,
      SeqNo commit_seqno) override
    {
      raft->force_become_leader(seqno, view, terms, commit_seqno);
    }

    bool replicate(const kv::BatchVector& entries, View view) override
    {
      return raft->replicate(entries, view);
    }

    std::pair<View, SeqNo> get_committed_txid() override
    {
      return raft->get_commit_term_and_idx();
    }

    View get_view(SeqNo seqno) override
    {
      return raft->get_term(seqno);
    }

    View get_view() override
    {
      return raft->get_term();
    }

    SeqNo get_committed_seqno() override
    {
      return raft->get_commit_idx();
    }

    NodeId primary() override
    {
      return raft->leader();
    }

    void recv_message(OArray&& data) override
    {
      return raft->recv_message(data.data(), data.size());
    }

    void add_configuration(
      SeqNo seqno, const Configuration::Nodes& conf) override
    {
      raft->add_configuration(seqno, conf);
    }

    Configuration::Nodes get_latest_configuration() const override
    {
      return raft->get_latest_configuration();
    }

    void periodic(std::chrono::milliseconds elapsed) override
    {
      raft->periodic(elapsed);
    }

    void enable_all_domains() override
    {
      raft->enable_all_domains();
    }

    void set_f(size_t) override
    {
      return;
    }

    void emit_signature() override
    {
      throw std::logic_error(
        "Method should not be called when using raft consensus");
    }

    ConsensusType type() override
    {
      return ConsensusType::RAFT;
    }
  };
}