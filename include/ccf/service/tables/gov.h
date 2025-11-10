// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/kv/map.h"
#include "ccf/service/tables/proposals.h"

namespace ccf::jsgov
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

  /// Proposal metadata stored in the KV
  struct ProposalInfo
  {
    /// ID of the member who originally created/submitted this proposal
    ccf::MemberId proposer_id;
    /// Current state of this proposal (eg - open, accepted, withdrawn)
    ccf::ProposalState state = ccf::ProposalState::OPEN;
    /// Collection of ballots (scripts) submitted for this proposal. Each
    /// ballot is a javascript module exporting a single 'vote' function,
    /// re-executed to determine the member's vote each proposal resolution.
    /// Keyed by each submitting member's ID
    Ballots ballots;
    /// Collection of boolean results of the submitted ballots, keyed by
    /// submitting member's ID, that caused a transition to a terminal state.
    /// Note that this is not present for open, withdrawn, or dropped
    /// proposals
    std::optional<Votes> final_votes = std::nullopt;
    /// Collection of exception details describing which ballots failed
    /// to execute successfully, keyed by submitting member's ID. Populated in
    /// the same circumstances as final_votes
    std::optional<VoteFailures> vote_failures = std::nullopt;
    /// Exception details from execution of the proposal itself, either during
    /// resolution or application. Populated in the same circumstances as
    /// final_votes
    std::optional<Failure> failure = std::nullopt;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ProposalInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ProposalInfo, proposer_id, state, ballots);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ProposalInfo, final_votes, vote_failures, failure);

  /// Proposal summary constructed while executing/resolving proposal ballots
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

  using ProposalMap =
    ccf::kv::RawCopySerialisedMap<ccf::ProposalId, std::vector<uint8_t>>;
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
    return format_to(ctx.out(), "N/A");
  }
};
FMT_END_NAMESPACE
