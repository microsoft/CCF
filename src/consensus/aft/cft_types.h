// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ecdsa.h"
#include "ccf/entity_id.h"
#include "consensus/consensus_types.h"
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

  static constexpr size_t starting_view_change = 2;

  class Store
  {
  public:
    virtual ~Store() = default;
    virtual void compact(Index v) = 0;
    virtual void rollback(
      const ccf::TxID& tx_id, Term term_of_next_version) = 0;
    virtual void initialise_term(Term t) = 0;
    virtual std::unique_ptr<ccf::kv::AbstractExecutionWrapper> deserialize(
      std::vector<uint8_t> data,
      bool public_only = false,
      const std::optional<ccf::TxID>& expected_txid = std::nullopt) = 0;
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

    void rollback(const ccf::TxID& tx_id, Term term_of_next_version) override
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

    std::unique_ptr<ccf::kv::AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t> data,
      bool public_only = false,
      const std::optional<ccf::TxID>& expected_txid = std::nullopt) override
    {
      auto p = x.lock();
      if (p)
      {
        return p->deserialize(data, public_only, expected_txid);
      }
      return nullptr;
    }
  };

  // NOLINTNEXTLINE(performance-enum-size)
  enum CftMsgType : Node2NodeMsg
  {
    cft_append_entries = 0,
    cft_append_entries_response,
    cft_append_entries_signed_response,
    cft_request_vote,
    cft_request_vote_response,
    cft_propose_request_vote,
    cft_request_pre_vote,
    cft_request_pre_vote_response,
  };

  DECLARE_JSON_ENUM(
    CftMsgType,
    {
      {CftMsgType::cft_append_entries, "cft_append_entries"},
      {CftMsgType::cft_append_entries_response, "cft_append_entries_response"},
      {CftMsgType::cft_append_entries_signed_response,
       "cft_append_entries_signed_response"},
      {CftMsgType::cft_request_vote, "cft_request_vote"},
      {CftMsgType::cft_request_vote_response, "cft_request_vote_response"},
      {CftMsgType::cft_propose_request_vote, "cft_propose_request_vote"},
      {CftMsgType::cft_request_pre_vote, "cft_request_pre_vote"},
      {CftMsgType::cft_request_pre_vote_response,
       "cft_request_pre_vote_response"},
    });

#pragma pack(push, 1)

  template <CftMsgType M>
  struct CftHeader
  {
    CftMsgType msg = M;
  };

  DECLARE_JSON_TYPE(CftHeader<cft_append_entries>);
  DECLARE_JSON_REQUIRED_FIELDS(CftHeader<cft_append_entries>, msg);

  struct AppendEntries : CftHeader<cft_append_entries>,
                         ::consensus::AppendEntriesIndex
  {
    Term term;
    Term prev_term;
    Index leader_commit_idx;
    // An AppendEntries now contains entries for a single term. So this
    // describes the term of all entries in the range, and if this is different
    // from prev_term, then the first entry is the first transaction in that new
    // term
    Term term_of_idx;
    // This is unused by the current implementation, but is kept to preserve
    // wire compatibility with previous versions of the code.
    bool contains_new_view = false;
  };

  DECLARE_JSON_TYPE_WITH_2BASES(
    AppendEntries,
    CftHeader<cft_append_entries>,
    ::consensus::AppendEntriesIndex);
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

  DECLARE_JSON_TYPE(CftHeader<cft_append_entries_response>);
  DECLARE_JSON_REQUIRED_FIELDS(CftHeader<cft_append_entries_response>, msg);

  struct AppendEntriesResponse : CftHeader<cft_append_entries_response>
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

  DECLARE_JSON_TYPE_WITH_BASE(
    AppendEntriesResponse, CftHeader<cft_append_entries_response>);
  DECLARE_JSON_REQUIRED_FIELDS(
    AppendEntriesResponse, term, last_log_idx, success);

  enum ElectionType : std::uint8_t
  {
    PreVote = 0,
    RegularVote = 1
  };

  DECLARE_JSON_ENUM(
    ElectionType,
    {{ElectionType::PreVote, "PreVote"},
     {ElectionType::RegularVote, "RegularVote"}});

  DECLARE_JSON_TYPE(CftHeader<cft_request_vote>);
  DECLARE_JSON_REQUIRED_FIELDS(CftHeader<cft_request_vote>, msg);

  struct RequestVote : CftHeader<cft_request_vote>
  {
    Term term;
    Index last_committable_idx;
    Term term_of_last_committable_idx;
  };

  DECLARE_JSON_TYPE_WITH_BASE(RequestVote, CftHeader<cft_request_vote>);
  DECLARE_JSON_REQUIRED_FIELDS(
    RequestVote, term, last_committable_idx, term_of_last_committable_idx);

  DECLARE_JSON_TYPE(CftHeader<cft_request_pre_vote>);
  DECLARE_JSON_REQUIRED_FIELDS(CftHeader<cft_request_pre_vote>, msg);

  struct RequestPreVote : CftHeader<cft_request_pre_vote>
  {
    Term term;
    Index last_committable_idx;
    Term term_of_last_committable_idx;
  };

  DECLARE_JSON_TYPE_WITH_BASE(RequestPreVote, CftHeader<cft_request_pre_vote>);
  DECLARE_JSON_REQUIRED_FIELDS(
    RequestPreVote, term, last_committable_idx, term_of_last_committable_idx);

  DECLARE_JSON_TYPE(CftHeader<cft_request_vote_response>);
  DECLARE_JSON_REQUIRED_FIELDS(CftHeader<cft_request_vote_response>, msg);

  struct RequestVoteResponse : CftHeader<cft_request_vote_response>
  {
    Term term;
    bool vote_granted;
  };

  DECLARE_JSON_TYPE_WITH_BASE(
    RequestVoteResponse, CftHeader<cft_request_vote_response>);
  DECLARE_JSON_REQUIRED_FIELDS(RequestVoteResponse, term, vote_granted);

  DECLARE_JSON_TYPE(CftHeader<cft_request_pre_vote_response>);
  DECLARE_JSON_REQUIRED_FIELDS(CftHeader<cft_request_pre_vote_response>, msg);

  struct RequestPreVoteResponse : CftHeader<cft_request_pre_vote_response>
  {
    Term term;
    bool vote_granted;
  };

  DECLARE_JSON_TYPE_WITH_BASE(
    RequestPreVoteResponse, CftHeader<cft_request_pre_vote_response>);
  DECLARE_JSON_REQUIRED_FIELDS(RequestPreVoteResponse, term, vote_granted);

  DECLARE_JSON_TYPE(CftHeader<cft_propose_request_vote>);
  DECLARE_JSON_REQUIRED_FIELDS(CftHeader<cft_propose_request_vote>, msg);

  struct ProposeRequestVote : CftHeader<cft_propose_request_vote>
  {
    // A node sends this to nudge another node to begin an election, for
    // instance because the sender is a retiring primary
    Term term;
  };

  DECLARE_JSON_TYPE_WITH_BASE(
    ProposeRequestVote, CftHeader<cft_propose_request_vote>);
  DECLARE_JSON_REQUIRED_FIELDS(ProposeRequestVote, term);

#pragma pack(pop)
}

FMT_BEGIN_NAMESPACE

template <>
struct formatter<aft::CftMsgType>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const aft::CftMsgType& msg_type, FormatContext& ctx) const
    -> decltype(ctx.out())
  {
    switch (msg_type)
    {
      case (aft::CftMsgType::cft_append_entries):
      {
        return fmt::format_to(ctx.out(), "append_entries");
      }
      case (aft::CftMsgType::cft_append_entries_response):
      {
        return fmt::format_to(ctx.out(), "append_entries_response");
      }
      case (aft::CftMsgType::cft_append_entries_signed_response):
      {
        return fmt::format_to(ctx.out(), "append_entries_signed_response");
      }
      case (aft::CftMsgType::cft_request_vote):
      {
        return fmt::format_to(ctx.out(), "request_vote");
      }
      case (aft::CftMsgType::cft_request_vote_response):
      {
        return fmt::format_to(ctx.out(), "request_vote_response");
      }
      case (aft::CftMsgType::cft_propose_request_vote):
      {
        return fmt::format_to(ctx.out(), "propose_request_vote");
      }
      case (aft::CftMsgType::cft_request_pre_vote):
      {
        return fmt::format_to(ctx.out(), "request_pre_vote");
      }
      case (aft::CftMsgType::cft_request_pre_vote_response):
      {
        return fmt::format_to(ctx.out(), "request_pre_vote_response");
      }
      default:
      {
        throw std::runtime_error(
          fmt::format("Unhandled CftMsgType: {}", uint64_t(msg_type)));
      }
    }
  }
};

FMT_END_NAMESPACE
