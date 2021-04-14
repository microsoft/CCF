// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"
#include "script.h"
#include "service_map.h"

#include <unordered_map>
#include <vector>

namespace ccf
{
  /** Members use proposals to propose changes to the public governance tables in the KV store.
   * Active members can issue proposals.
   * These proposals are stored in the KV, and passed to the JS constitution functions for validation and execution.
   */
  enum class ProposalState
  {
    OPEN, //< Proposal is active and can be voted on
    ACCEPTED, //< Proposal passed a successful vote and was enacted
    WITHDRAWN, //< Proposal was removed by proposing member, will never be
               // enacted
    REJECTED, //< Proposal was rejected by vote, will never be enacted
    FAILED, //< Proposal passed a successful vote, but its proposed actions
            // failed, will never be enacted
    DROPPED, //< Proposal was open when its semantics were potentially changed
             // (code or constitution were modified), so it was automatically
             // invalidated and dropped
  };
  DECLARE_JSON_ENUM(
    ProposalState,
    {{ProposalState::OPEN, "Open"},
     {ProposalState::ACCEPTED, "Accepted"},
     {ProposalState::WITHDRAWN, "Withdrawn"},
     {ProposalState::REJECTED, "Rejected"},
     {ProposalState::FAILED, "Failed"},
     {ProposalState::DROPPED, "Dropped"}});

  struct Proposal
  {
    Script script = {};
    nlohmann::json parameter = {};
    MemberId proposer = {};
    ProposalState state = ProposalState::OPEN;
    std::unordered_map<MemberId, Script> votes = {};

    Proposal() = default;
    Proposal(const Script& s, const nlohmann::json& param, MemberId prop) :
      script(s),
      parameter(param),
      proposer(prop),
      state(ProposalState::OPEN)
    {}

    bool operator==(const Proposal& o) const
    {
      return script == o.script && parameter == o.parameter &&
        proposer == o.proposer && state == o.state && votes == o.votes;
    }
  };
  DECLARE_JSON_TYPE(Proposal)
  DECLARE_JSON_REQUIRED_FIELDS(
    Proposal, script, parameter, proposer, state, votes)

  using ProposalId = std::string;
  using Proposals = ServiceMap<ProposalId, Proposal>;

  struct ProposalInfo
  {
    ProposalId proposal_id;
    MemberId proposer_id;
    ProposalState state;
  };
  DECLARE_JSON_TYPE(ProposalInfo)
  DECLARE_JSON_REQUIRED_FIELDS(ProposalInfo, proposal_id, proposer_id, state);

  struct Vote
  {
    Script ballot;
  };
  DECLARE_JSON_TYPE(Vote)
  DECLARE_JSON_REQUIRED_FIELDS(Vote, ballot)

  struct KVRead
  {
    struct In
    {
      std::string table = {};
      nlohmann::json key = {};
    };

    using Out = nlohmann::json;
  };
  DECLARE_JSON_TYPE(KVRead::In)
  DECLARE_JSON_REQUIRED_FIELDS(KVRead::In, table, key);

  enum CompletionResult
  {
    PASSED = 1,
    PENDING = 0,
    REJECTED = -1
  };
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::ProposalState>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::ProposalState& state, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    switch (state)
    {
      case (ccf::ProposalState::OPEN):
      {
        return format_to(ctx.out(), "open");
      }
      case (ccf::ProposalState::ACCEPTED):
      {
        return format_to(ctx.out(), "accepted");
      }
      case (ccf::ProposalState::WITHDRAWN):
      {
        return format_to(ctx.out(), "withdrawn");
      }
      case (ccf::ProposalState::REJECTED):
      {
        return format_to(ctx.out(), "rejected");
      }
      case (ccf::ProposalState::DROPPED):
      {
        return format_to(ctx.out(), "dropped");
      }
      default:
      {
        return format_to(ctx.out(), "UNKNOWN");
      }
    }
  }
};
FMT_END_NAMESPACE
