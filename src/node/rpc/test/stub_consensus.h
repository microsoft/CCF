// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft.h"
#include "consensus/aft/request.h"
#include "kv/kv_types.h"

#include <memory>

namespace aft
{
  class StubCFTConsensus : public kv::Consensus
  {
  public:
    StubCFTConsensus() : kv::Consensus(0) {}
    bool is_primary() override
    {
      return true;
    }
    bool is_backup() override
    {
      return false;
    }
    void force_become_primary() override {}
    void force_become_primary(
      SeqNo seqno,
      View view,
      const std::vector<kv::Version>& terms,
      SeqNo commit_seqno) override
    {}
    void init_as_backup(
      SeqNo seqno,
      View view,
      const std::vector<kv::Version>& view_history) override
    {}
    bool replicate(const kv::BatchVector& entries, View view) override
    {
      return true;
    }
    std::pair<View, SeqNo> get_committed_txid() override
    {
      return {0, 0};
    }
    std::optional<SignableTxIndices> get_signable_txid() override
    {
      return std::nullopt;
    }
    View get_view(SeqNo seqno) override
    {
      return 0;
    }
    View get_view() override
    {
      return 0;
    }
    std::vector<SeqNo> get_view_history(SeqNo seqno) override
    {
      return {};
    }
    void initialise_view_history(
      const std::vector<SeqNo>& view_history) override
    {}
    SeqNo get_committed_seqno() override
    {
      return 0;
    }
    NodeId primary() override
    {
      return 0;
    }
    bool view_change_in_progress() override
    {
      return false;
    }
    std::set<NodeId> active_nodes() override
    {
      return {0};
    }
    void recv_message(OArray&& data) override {}
    void add_configuration(
      SeqNo seqno, const Configuration::Nodes& conf) override
    {}
    Configuration::Nodes get_latest_configuration() const override
    {
      return {};
    }
    void periodic(std::chrono::milliseconds elapsed) override {}

    void enable_all_domains() override {}

    uint32_t node_count() override
    {
      return 0;
    }

    void emit_signature() override {}

    bool on_request(const kv::TxHistory::RequestCallbackArgs& args) override
    {
      return true;
    }

    ConsensusType type() override
    {
      return ConsensusType::CFT;
    }
  };

}