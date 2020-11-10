// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "ds/msgpack_adaptor_nlohmann.h"
#include "entities.h"
#include "kv/map.h"
#include "script.h"

#include <msgpack/msgpack.hpp>
#include <unordered_map>
#include <vector>

namespace ccf
{
  /** Members use proposals to propose changes to the KV store.
   * Active members can issue proposals through the Propose RPC.
   * A proposal is defined by a Lua script and a corresponding parameter.
   * Proposal are passed two arguments:
   *  (1) a table mapping KV store table names to corresponding accessors
   *  (2) the specified parameter (which is translated from json to Lua, this
   * could for example be the certificate of a to-be-added node).
   * Proposal scripts can read KV tables with the rights of the proposing
   * member, but they cannot write. Proposal scripts must return a list of
   * proposed function calls (ie, ::ProposedCalls). For this, they have access
   * to the helper class Calls. If a script returns an empty list, the vote is
   * aborted and it may run again at a later point. The available function calls
   * are defined in
   * ::MemberRpcFrontend and gov.lua. The following script proposes calling
   * "raw_puts" (defined in gov.lua) to make raw writes to the KV. It uses the
   * helper class Puts. (The environment for proposal scripts is defined
   * ./src/runtime_config/gov.lua.)
   *
   *  local tables, param = ...
   *  local value = tables["public:ccf.gov.values"]:get(param)
   *  local c = Calls:new()
   *  local p = Puts:new()
   *  -- propose writing store["table"]["key"] = value
   *  p:put("table", "key", value)
   *  c:call("raw_puts", p)
   *  return c
   *
   * Or more compact:
   *
   *  local tables, param = ...
   *  return Calls:call(Puts:put("table", "key",
   *    tables["public:ccf.gov.values"]:get(param))
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
  };
  DECLARE_JSON_ENUM(
    ProposalState,
    {{ProposalState::OPEN, "OPEN"},
     {ProposalState::ACCEPTED, "ACCEPTED"},
     {ProposalState::WITHDRAWN, "WITHDRAWN"},
     {ProposalState::REJECTED, "REJECTED"},
     {ProposalState::FAILED, "FAILED"}});

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

    MSGPACK_DEFINE(script, parameter, proposer, state, votes);
  };
  DECLARE_JSON_TYPE(Proposal)
  DECLARE_JSON_REQUIRED_FIELDS(
    Proposal, script, parameter, proposer, state, votes)

  using Proposals = kv::Map<ObjectId, Proposal>;

  struct ProposalInfo
  {
    ObjectId proposal_id;
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

  //! A call proposed by a proposal script
  struct ProposedCall
  {
    //! the name of the function to call
    std::string func;
    //! the corresponding arguments
    nlohmann::json args;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ProposedCall)
  DECLARE_JSON_REQUIRED_FIELDS(ProposedCall, func)
  DECLARE_JSON_OPTIONAL_FIELDS(ProposedCall, args)

  struct Propose
  {
    //! arguments for propose RPC
    struct In
    {
      //! script that proposes changes
      Script script;
      //! fixed parameter for the script
      nlohmann::json parameter = nullptr;
    };

    //! results from propose RPC
    using Out = ProposalInfo;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Propose::In)
  DECLARE_JSON_REQUIRED_FIELDS(Propose::In, script)
  DECLARE_JSON_OPTIONAL_FIELDS(Propose::In, parameter)

  /** A list of calls proposed (and returned) by a proposal script
   * Every proposal script must return a compatible data structure.
   */
  using ProposedCalls = std::vector<ProposedCall>;

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

MSGPACK_ADD_ENUM(ccf::ProposalState);

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
        return format_to(ctx.out(), "reject");
      }
      default:
      {
        return format_to(ctx.out(), "UNKNOWN");
      }
    }
  }
};
FMT_END_NAMESPACE
