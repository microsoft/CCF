// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/consensus_types.h"
#include "ds/ring_buffer_types.h"
#include "enclave/rpc_context.h"
#include "enclave/rpc_handler.h"
#include "kv/kv_types.h"

#include <chrono>
#include <cstdint>
#include <limits>

namespace aft
{
  using Index = int64_t;
  using Term = int64_t;
  using NodeId = uint64_t;
  using Node2NodeMsg = uint64_t;

  using ReplyCallback = std::function<bool(
    void* owner,
    kv::TxHistory::RequestID caller_rid,
    int status,
    std::vector<uint8_t>& data)>;

  static constexpr NodeId NoNode = std::numeric_limits<NodeId>::max();

  template <typename S>
  class Store
  {
  public:
    virtual ~Store() {}
    virtual S deserialise(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr) = 0;
    virtual void compact(Index v) = 0;
    virtual void rollback(Index v, std::optional<Term> t = std::nullopt) = 0;
    virtual void set_term(Term t) = 0;
    virtual S deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      kv::Term* term = nullptr,
      kv::Tx* tx = nullptr) = 0;
  };

  template <typename T, typename S>
  class Adaptor : public Store<S>
  {
  private:
    std::weak_ptr<T> x;

  public:
    Adaptor(std::shared_ptr<T> x) : x(x) {}

    S deserialise(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr) override
    {
      auto p = x.lock();
      if (p)
      {
        return p->deserialise(data, public_only, term);
      }
      return S::FAILED;
    }

    void compact(Index v) override
    {
      auto p = x.lock();
      if (p)
      {
        p->compact(v);
      }
    }

    void rollback(Index v, std::optional<Term> t = std::nullopt) override
    {
      auto p = x.lock();
      if (p)
      {
        p->rollback(v, t);
      }
    }

    void set_term(Term t) override
    {
      auto p = x.lock();
      if (p)
      {
        p->set_term(t);
      }
    }

    S deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      kv::Term* term = nullptr,
      kv::Tx* tx = nullptr) override
    {
      auto p = x.lock();
      if (p)
        return p->deserialise_views(data, public_only, term, tx);
      return S::FAILED;
    }
  };

  enum RaftMsgType : Node2NodeMsg
  {
    raft_append_entries = 0,
    raft_append_entries_response,
    raft_request_vote,
    raft_request_vote_response,

    bft_request,
  };

#pragma pack(push, 1)
  struct RaftHeader
  {
    RaftMsgType msg;
    NodeId from_node;
  };

  struct AppendEntries : consensus::ConsensusHeader<RaftMsgType>,
                         consensus::AppendEntriesIndex
  {
    Term term;
    Term prev_term;
    Index leader_commit_idx;
    Term term_of_idx;
  };

  struct AppendEntriesResponse : RaftHeader
  {
    Term term;
    Index last_log_idx;
    bool success;
  };

  struct RequestVote : RaftHeader
  {
    Term term;
    Index last_commit_idx;
    Term last_commit_term;
    Index last_committable_idx;
  };

  struct RequestVoteResponse : RaftHeader
  {
    Term term;
    bool vote_granted;
  };
#pragma pack(pop)
}