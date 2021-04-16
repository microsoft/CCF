// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"
#include "kv/map.h"
#include "proposals.h"

namespace ccf
{
  namespace jsgov
  {
    using ProposalId = std::string;
    using Ballots = std::unordered_map<ccf::MemberId, std::string>;
    using Votes = std::unordered_map<ccf::MemberId, bool>;

    struct Failure
    {
      std::string reason;
      std::string trace;
      bool operator==(const Failure& rhs) const
      {
        return reason == rhs.reason && trace == rhs.trace;
      }
    };
    DECLARE_JSON_TYPE(Failure);
    DECLARE_JSON_REQUIRED_FIELDS(Failure, reason, trace);
    using VoteFailures = std::unordered_map<ccf::MemberId, Failure>;

    struct ProposalInfo
    {
      ccf::MemberId proposer_id;
      ccf::ProposalState state;
      Ballots ballots = {};
      std::optional<Votes> final_votes = {};
      std::optional<VoteFailures> vote_failures = {};
      std::optional<std::string> failure_reason = std::nullopt;
      std::optional<std::string> failure_trace = std::nullopt;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ProposalInfo);
    DECLARE_JSON_REQUIRED_FIELDS(ProposalInfo, proposer_id, state, ballots);
    DECLARE_JSON_OPTIONAL_FIELDS(
      ProposalInfo, final_votes, failure_reason, failure_trace);

    struct ProposalInfoSummary
    {
      ProposalId proposal_id;
      ccf::MemberId proposer_id;
      ccf::ProposalState state;
      size_t ballot_count;
      std::optional<Votes> votes = {};
      std::optional<VoteFailures> vote_failures = {};
      std::optional<std::string> failure_reason = std::nullopt;
      std::optional<std::string> failure_trace = std::nullopt;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ProposalInfoSummary);
    DECLARE_JSON_REQUIRED_FIELDS(
      ProposalInfoSummary, proposal_id, proposer_id, state, ballot_count);
    DECLARE_JSON_OPTIONAL_FIELDS(
      ProposalInfoSummary, votes, vote_failures, failure_reason, failure_trace);

    struct ProposalInfoDetails
    {
      /// Proposal ID
      ProposalId proposal_id;
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
      kv::RawCopySerialisedMap<ProposalId, std::vector<uint8_t>>;
    using ProposalInfoMap = ServiceMap<ProposalId, ProposalInfo>;

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