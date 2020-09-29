// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/consensus_types.h"
#include "ds/ring_buffer_types.h"
#include "enclave/rpc_context.h"
#include "enclave/rpc_handler.h"
#include "kv/kv_types.h"
#include "mbedtls/ecdsa.h"
#include "node/progress_tracker.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <limits>

namespace aft
{
  using Index = int64_t;
  using Term = int64_t;
  using NodeId = uint64_t;
  using Node2NodeMsg = uint64_t;
  using Nonce = std::array<uint8_t, 32>;

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
      kv::Tx* tx = nullptr,
      ccf::PrimarySignature* sig = nullptr) = 0;
    virtual std::shared_ptr<ccf::ProgressTracker> get_progress_tracker() = 0;
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

    std::shared_ptr<ccf::ProgressTracker> get_progress_tracker() override
    {
      auto p = x.lock();
      if (p)
      {
        return p->get_progress_tracker();
      }
      return nullptr;
    }

    S deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      kv::Term* term = nullptr,
      kv::Tx* tx = nullptr,
      ccf::PrimarySignature* sig = nullptr) override
    {
      auto p = x.lock();
      if (p)
        return p->deserialise_views(data, public_only, term, tx, sig);
      return S::FAILED;
    }
  };

  enum RaftMsgType : Node2NodeMsg
  {
    raft_append_entries = 0,
    raft_append_entries_response,
    raft_append_entries_signed_response,
    raft_request_vote,
    raft_request_vote_response,

    bft_request,
    bft_signature_received_ack,
    bft_nonce_reveal
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

  struct SignedAppendEntriesResponse : RaftHeader
  {
    Term term;
    Index last_log_idx;
    Nonce hashed_nonce;
    uint32_t signature_size;
    std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN> sig;
  };

  struct SignaturesReceivedAck : RaftHeader
  {
    Term term;
    Index idx;
  };

  struct NonceRevealMsg : RaftHeader
  {
    Term term;
    Index idx;
    Nonce nonce;
  };

  struct RequestVote : RaftHeader
  {
    Term term;
    // last_log_idx in vanilla raft but last_commit_idx here to preserve
    // verifiability
    Index last_commit_idx;
    // last_log_term in vanilla raft but last_commit_term here to preserve
    // verifiability
    Term last_commit_term;
  };

  struct RequestVoteResponse : RaftHeader
  {
    Term term;
    bool vote_granted;
  };
#pragma pack(pop)
}