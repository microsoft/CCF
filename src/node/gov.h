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

    struct ProposalInfo
    {
      ccf::MemberId proposer_id;
      ccf::ProposalState state;
      std::unordered_map<ccf::MemberId, std::string> ballots = {};
      std::unordered_map<ccf::MemberId, bool> final_votes = {};
      std::optional<std::string> failure_reason = std::nullopt;
      std::optional<std::string> failure_trace = std::nullopt;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ProposalInfo);
    DECLARE_JSON_REQUIRED_FIELDS(
      ProposalInfo, proposer_id, state, ballots, final_votes);
    DECLARE_JSON_OPTIONAL_FIELDS(ProposalInfo, failure_reason, failure_trace);

    struct ProposalInfoSummary
    {
      ProposalId proposal_id;
      ccf::MemberId proposer_id;
      ccf::ProposalState state;
      size_t ballot_count;
      std::unordered_map<ccf::MemberId, bool> votes = {};
      std::optional<std::string> failure_reason = std::nullopt;
      std::optional<std::string> failure_trace = std::nullopt;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ProposalInfoSummary);
    DECLARE_JSON_REQUIRED_FIELDS(
      ProposalInfoSummary,
      proposal_id,
      proposer_id,
      state,
      ballot_count,
      votes);
    DECLARE_JSON_OPTIONAL_FIELDS(
      ProposalInfoSummary, failure_reason, failure_trace);

    struct ProposalInfoDetails
    {
      /// Proposal ID
      ProposalId proposal_id;
      /// Member ID of the proposer
      ccf::MemberId proposer_id;
      /// Proposal state
      ccf::ProposalState state;
      /// Ballots (scripts) submitted for the proposal
      std::unordered_map<ccf::MemberId, std::string> ballots = {};
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