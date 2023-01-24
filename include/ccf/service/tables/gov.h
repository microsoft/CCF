// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/kv/map.h"
#include "ccf/service/tables/proposals.h"

namespace ccf
{
  namespace jsgov
  {
    using Ballots = std::unordered_map<ccf::MemberId, std::string>;
    using Votes = std::unordered_map<ccf::MemberId, bool>;

    struct Failure
    {
      std::string reason;
      std::optional<std::string> trace;
      bool operator==(const Failure& rhs) const
      {
        return reason == rhs.reason && trace == rhs.trace;
      }
      bool operator!=(const Failure& rhs) const
      {
        return !(*this == rhs);
      }
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Failure);
    DECLARE_JSON_REQUIRED_FIELDS(Failure, reason);
    DECLARE_JSON_OPTIONAL_FIELDS(Failure, trace);
    using VoteFailures = std::unordered_map<ccf::MemberId, Failure>;

    struct ProposalInfo
    {
      ccf::MemberId proposer_id;
      ccf::ProposalState state;
      Ballots ballots = {};
      std::optional<Votes> final_votes = std::nullopt;
      std::optional<VoteFailures> vote_failures = std::nullopt;
      std::optional<Failure> failure = std::nullopt;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ProposalInfo);
    DECLARE_JSON_REQUIRED_FIELDS(ProposalInfo, proposer_id, state, ballots);
    DECLARE_JSON_OPTIONAL_FIELDS(
      ProposalInfo, final_votes, vote_failures, failure);

    struct ProposalInfoSummary
    {
      ccf::ProposalId proposal_id;
      ccf::MemberId proposer_id;
      ccf::ProposalState state;
      size_t ballot_count;
      std::optional<Votes> votes = std::nullopt;
      std::optional<VoteFailures> vote_failures = std::nullopt;
      std::optional<Failure> failure = std::nullopt;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ProposalInfoSummary);
    DECLARE_JSON_REQUIRED_FIELDS(
      ProposalInfoSummary, proposal_id, proposer_id, state, ballot_count);
    DECLARE_JSON_OPTIONAL_FIELDS(
      ProposalInfoSummary, votes, vote_failures, failure);

    struct ProposalInfoDetails
    {
      /// Proposal ID
      ccf::ProposalId proposal_id;
      /// Member ID of the proposer
      ccf::MemberId proposer_id;
      /// Proposal state
      ccf::ProposalState state;
      /// Ballots (scripts) submitted for the proposal
      Ballots ballots = {};
    };
    DECLARE_JSON_TYPE(ProposalInfoDetails);
    DECLARE_JSON_REQUIRED_FIELDS(
      ProposalInfoDetails, proposal_id, proposer_id, state, ballots);

    using ProposalMap =
      kv::RawCopySerialisedMap<ccf::ProposalId, std::vector<uint8_t>>;
    using ProposalInfoMap = ServiceMap<ccf::ProposalId, ProposalInfo>;

    namespace Tables
    {
      static constexpr auto PROPOSALS = "public:ccf.gov.proposals";
      static constexpr auto PROPOSALS_INFO = "public:ccf.gov.proposals_info";
    }

    struct Action
    {
      std::string name;
      nlohmann::json args;
    };
    DECLARE_JSON_TYPE(Action);
    DECLARE_JSON_REQUIRED_FIELDS(Action, name, args);

    struct Proposal
    {
      std::vector<Action> actions;
    };
    DECLARE_JSON_TYPE(Proposal);
    DECLARE_JSON_REQUIRED_FIELDS(Proposal, actions);

    struct Ballot
    {
      std::string ballot;
    };
    DECLARE_JSON_TYPE(Ballot);
    DECLARE_JSON_REQUIRED_FIELDS(Ballot, ballot);
  }
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<std::optional<ccf::jsgov::Failure>>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(
    const std::optional<ccf::jsgov::Failure>& f, FormatContext& ctx) const
  {
    if (f.has_value())
    {
      return format_to(
        ctx.out(), "{}\nTrace: {}", f->reason, f->trace.value_or("N/A"));
    }
    else
    {
      return format_to(ctx.out(), "N/A");
    }
  }
};
FMT_END_NAMESPACE
