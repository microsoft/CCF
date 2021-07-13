// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "consensus/consensus_types.h"
#include "crypto/hash.h"
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
  using Index = uint64_t;
  using Term = uint64_t;
  using Node2NodeMsg = uint64_t;
  using Nonce = crypto::Sha256Hash;

  using ReplyCallback = std::function<bool(
    void* owner,
    kv::TxHistory::RequestID caller_rid,
    int status,
    std::vector<uint8_t>&& data)>;

  static constexpr size_t starting_view_change = 2;

  class Store
  {
  public:
    virtual ~Store() {}
    virtual void compact(Index v) = 0;
    virtual void rollback(const kv::TxID& tx_id, Term term_of_next_version) = 0;
    virtual void initialise_term(Term t) = 0;
    virtual std::unique_ptr<kv::AbstractExecutionWrapper> apply(
      const std::vector<uint8_t> data,
      ConsensusType consensus_type,
      bool public_only = false) = 0;
    virtual std::shared_ptr<ccf::ProgressTracker> get_progress_tracker() = 0;
  };

  template <typename T>
  class Adaptor : public Store
  {
  private:
    std::weak_ptr<T> x;

  public:
    Adaptor(std::shared_ptr<T> x) : x(x) {}

    void compact(Index v) override
    {
      auto p = x.lock();
      if (p)
      {
        p->compact(v);
      }
    }

    void rollback(const kv::TxID& tx_id, Term term_of_next_version) override
    {
      auto p = x.lock();
      if (p)
      {
        p->rollback(tx_id, term_of_next_version);
      }
    }

    void initialise_term(Term t) override
    {
      auto p = x.lock();
      if (p)
      {
        p->initialise_term(t);
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

    std::unique_ptr<kv::AbstractExecutionWrapper> apply(
      const std::vector<uint8_t> data,
      ConsensusType consensus_type,
      bool public_only = false) override
    {
      auto p = x.lock();
      if (p)
      {
        return p->deserialize(data, consensus_type, public_only);
      }
      return nullptr;
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
    bft_nonce_reveal,
    bft_view_change,
    bft_view_change_evidence,
    bft_skip_view,
  };

#pragma pack(push, 1)
  struct RaftHeader
  {
    RaftMsgType msg;
  };

  struct AppendEntries : RaftHeader, consensus::AppendEntriesIndex
  {
    Term term;
    Term prev_term;
    Index leader_commit_idx;
    Term term_of_idx;
    bool contains_new_view;
  };

  enum class AppendEntriesResponseType : uint8_t
  {
    OK = 0,
    FAIL = 1,
    REQUIRE_EVIDENCE = 2
  };

  struct AppendEntriesResponse : RaftHeader
  {
    Term term;
    Index last_log_idx;
    AppendEntriesResponseType success;
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

  struct RequestViewChangeMsg : RaftHeader
  {
    ccf::View view = 0;
    ccf::SeqNo seqno = 0;
  };

  struct ViewChangeEvidenceMsg : RaftHeader
  {
    ccf::View view = 0;
  };

  struct SkipViewMsg : RaftHeader
  {
    ccf::View view = 0;
  };

  struct RequestVote : RaftHeader
  {
    Term term;
    Index last_committable_idx;
    Term term_of_last_committable_idx;
  };

  struct RequestVoteResponse : RaftHeader
  {
    Term term;
    bool vote_granted;
  };
#pragma pack(pop)
}