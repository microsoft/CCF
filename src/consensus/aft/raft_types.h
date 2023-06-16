// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ecdsa.h"
#include "ccf/entity_id.h"
#include "consensus/consensus_types.h"
#include "ds/ring_buffer_types.h"
#include "enclave/rpc_handler.h"
#include "kv/kv_types.h"

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
      bool public_only = false,
      const std::optional<kv::TxID>& expected_txid = std::nullopt) = 0;
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

    std::unique_ptr<kv::AbstractExecutionWrapper> apply(
      const std::vector<uint8_t> data,
      bool public_only = false,
      const std::optional<kv::TxID>& expected_txid = std::nullopt) override
    {
      auto p = x.lock();
      if (p)
      {
        return p->deserialize(data, public_only, expected_txid);
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
    raft_request_vote_response
  };
  DECLARE_JSON_ENUM(
    RaftMsgType,
    {
      {RaftMsgType::raft_append_entries, "raft_append_entries"},
      {RaftMsgType::raft_append_entries_response,
       "raft_append_entries_response"},
      {RaftMsgType::raft_append_entries_signed_response,
       "raft_append_entries_signed_response"},
      {RaftMsgType::raft_request_vote, "raft_request_vote"},
      {RaftMsgType::raft_request_vote_response, "raft_request_vote_response"},
    });

#pragma pack(push, 1)
  struct RaftHeader
  {
    RaftMsgType msg;
  };
  DECLARE_JSON_TYPE(RaftHeader);
  DECLARE_JSON_REQUIRED_FIELDS(RaftHeader, msg);

  struct AppendEntries : RaftHeader, consensus::AppendEntriesIndex
  {
    Term term;
    Term prev_term;
    Index leader_commit_idx;
    // An AppendEntries now contains entries for a single term. So this
    // describes the term of all entries in the range, and if this is different
    // from prev_term, then the first entry is the first transaction in that new
    // term
    Term term_of_idx;
    bool contains_new_view;
  };
  DECLARE_JSON_TYPE_WITH_2BASES(
    AppendEntries, RaftHeader, consensus::AppendEntriesIndex);
  DECLARE_JSON_REQUIRED_FIELDS(
    AppendEntries,
    term,
    prev_term,
    leader_commit_idx,
    term_of_idx,
    contains_new_view);

  enum class AppendEntriesResponseType : uint8_t
  {
    OK = 0,
    FAIL = 1
  };
  DECLARE_JSON_ENUM(
    AppendEntriesResponseType,
    {{AppendEntriesResponseType::OK, "OK"},
     {AppendEntriesResponseType::FAIL, "FAIL"}});

  struct AppendEntriesResponse : RaftHeader
  {
    // This term and idx usually refer to the tail of the sender's log. The
    // exception is in a rejection because of a mismatching suffix, in which
    // case this describes the latest point that the local node believes may
    // still match the leader's (which may be from an old term!). In either case
    // this can be treated as the _latest possible_ matching index for this
    // follower. Note this may still be higher than the true match index, so
    // should not affect the leader's opinion of how matched the follower is.
    // Only a positive response should modify match_idx.
    Term term;
    Index last_log_idx;
    AppendEntriesResponseType success;
  };
  DECLARE_JSON_TYPE_WITH_BASE(AppendEntriesResponse, RaftHeader);
  DECLARE_JSON_REQUIRED_FIELDS(
    AppendEntriesResponse, term, last_log_idx, success);

  struct RequestVote : RaftHeader
  {
    Term term;
    Index last_committable_idx;
    Term term_of_last_committable_idx;
  };
  DECLARE_JSON_TYPE_WITH_BASE(RequestVote, RaftHeader);
  DECLARE_JSON_REQUIRED_FIELDS(
    RequestVote, term, last_committable_idx, term_of_last_committable_idx);

  struct RequestVoteResponse : RaftHeader
  {
    Term term;
    bool vote_granted;
  };
  DECLARE_JSON_TYPE_WITH_BASE(RequestVoteResponse, RaftHeader);
  DECLARE_JSON_REQUIRED_FIELDS(RequestVoteResponse, term, vote_granted);

#pragma pack(pop)
}
