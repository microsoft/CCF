// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "raft.h"
#include "request.h"

#include <memory>

namespace aft
{
  // This class acts as an adapter between the generic Consensus API and
  // the AFT API, allowing for a mapping between the generic consensus
  // terminology and the terminology that is specific to AFT

  template <class... T>
  class Consensus : public kv::Consensus
  {
  private:
    std::unique_ptr<Aft<T...>> aft;
    ConsensusType consensus_type;

  public:
    Consensus(std::unique_ptr<Aft<T...>> raft_, ConsensusType consensus_type_) :
      kv::Consensus(raft_->id()),
      aft(std::move(raft_)),
      consensus_type(consensus_type_)
    {}

    bool is_primary() override
    {
      return aft->is_primary();
    }

    bool is_backup() override
    {
      return aft->is_follower();
    }

    void force_become_primary() override
    {
      aft->force_become_leader();
    }

    void force_become_primary(
      ccf::SeqNo seqno,
      ccf::View view,
      const std::vector<kv::Version>& terms,
      ccf::SeqNo commit_seqno) override
    {
      aft->force_become_leader(seqno, view, terms, commit_seqno);
    }

    void init_as_backup(
      ccf::SeqNo seqno,
      ccf::View view,
      const std::vector<kv::Version>& view_history) override
    {
      aft->init_as_follower(seqno, view, view_history);
    }

    bool replicate(const kv::BatchVector& entries, ccf::View view) override
    {
      return aft->replicate(entries, view);
    }

    std::pair<ccf::View, ccf::SeqNo> get_committed_txid() override
    {
      return aft->get_commit_term_and_idx();
    }

    std::optional<SignableTxIndices> get_signable_txid() override
    {
      return aft->get_signable_commit_term_and_idx();
    }

    ccf::View get_view(ccf::SeqNo seqno) override
    {
      return aft->get_term(seqno);
    }

    ccf::View get_view() override
    {
      return aft->get_term();
    }

    std::vector<ccf::SeqNo> get_view_history(ccf::SeqNo seqno) override
    {
      return aft->get_term_history(seqno);
    }

    void initialise_view_history(
      const std::vector<ccf::SeqNo>& view_history) override
    {
      aft->initialise_term_history(view_history);
    }

    ccf::SeqNo get_committed_seqno() override
    {
      return aft->get_commit_idx();
    }

    std::optional<ccf::NodeId> primary() override
    {
      return aft->leader();
    }

    bool view_change_in_progress() override
    {
      return aft->view_change_in_progress();
    }

    std::set<ccf::NodeId> active_nodes() override
    {
      return aft->active_nodes();
    }

    void recv_message(const ccf::NodeId& from, OArray&& data) override
    {
      return aft->recv_message(from, std::move(data));
    }

    void add_configuration(
      ccf::SeqNo seqno, const Configuration::Nodes& conf) override
    {
      aft->add_configuration(seqno, conf);
    }

    Configuration::Nodes get_latest_configuration() override
    {
      return aft->get_latest_configuration();
    }

    Configuration::Nodes get_latest_configuration_unsafe() const override
    {
      return aft->get_latest_configuration_unsafe();
    }

    std::vector<Configuration> get_active_configurations() override
    {
      return aft->get_active_configurations();
    }

    void periodic(std::chrono::milliseconds elapsed) override
    {
      aft->periodic(elapsed);
    }

    void enable_all_domains() override
    {
      aft->enable_all_domains();
    }

    uint32_t node_count() override
    {
      return aft->node_count();
    }

    void emit_signature() override {}

    bool on_request(const kv::TxHistory::RequestCallbackArgs& args) override
    {
      return aft->on_request(args);
    }

    ConsensusType type() override
    {
      return consensus_type;
    }
  };
}