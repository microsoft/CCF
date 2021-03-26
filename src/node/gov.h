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
    };
    DECLARE_JSON_TYPE(ProposalInfo);
    DECLARE_JSON_REQUIRED_FIELDS(ProposalInfo, proposer_id, state, ballots);

    struct ProposalSubmitted
    {
      ProposalId proposal_id;
      ccf::ProposalState state;
    };
    DECLARE_JSON_TYPE(ProposalSubmitted);
    DECLARE_JSON_REQUIRED_FIELDS(ProposalSubmitted, proposal_id, state);

    using ProposalMap = kv::RawCopySerialisedMap<ProposalId, std::string>;
    using ProposalInfoMap = kv::MapSerialisedWith<
      ProposalId,
      ProposalInfo,
      kv::serialisers::BlitSerialiser,
      kv::serialisers::JsonSerialiser>;

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