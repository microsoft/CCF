// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "ds/msgpack_adaptor_nlohmann.h"
#include "entities.h"
#include "script.h"

#include <msgpack-c/msgpack.hpp>
#include <unordered_map>
#include <vector>

namespace ccf
{
  // TODO(#feature): add optional explicit signatures to Proposal and Vote
  // as in the paper

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
   * ::MemberCallRpcFrontend and gov.lua. The following script proposes calling
   * "raw_puts" (defined in gov.lua) to make raw writes to the KV. It uses the
   * helper class Puts. (The environment for proposal scripts is defined
   * ./src/runtime_config/gov.lua.)
   *
   *  local tables, param = ...
   *  local value = tables["values"]:get(param)
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
   *  return Calls:call(Puts:put("table", "key", tables["values"]:get(param))
   */
  struct Propose
  {
    //! arguments for propose RPC
    struct In
    {
      //! script that proposes changes
      Script script;
      //! fixed parameter for the script
      nlohmann::json parameter;
      //! vote ballot of proposer
      Script ballot = {"return true"};
    };

    //! results from propose RPC
    struct Out
    {
      //! the id of the created proposal
      ObjectId id;
      //! the completion result
      bool completed;
    };
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Propose::In)
  DECLARE_JSON_REQUIRED_FIELDS(Propose::In, script, parameter)
  DECLARE_JSON_OPTIONAL_FIELDS(Propose::In, ballot)
  DECLARE_JSON_TYPE(Propose::Out)
  DECLARE_JSON_REQUIRED_FIELDS(Propose::Out, id, completed)

  enum class ProposalState
  {
    OPEN,
    ACCEPTED,
    WITHDRAWN,
  };
  DECLARE_JSON_ENUM(
    ProposalState,
    {{ProposalState::OPEN, "OPEN"},
     {ProposalState::ACCEPTED, "ACCEPTED"},
     {ProposalState::WITHDRAWN, "WITHDRAWN"}});

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

  using Proposals = Store::Map<ObjectId, Proposal>;

  struct ProposalAction
  {
    //! the id of the proposal subject to the action
    ObjectId id;
  };
  DECLARE_JSON_TYPE(ProposalAction)
  DECLARE_JSON_REQUIRED_FIELDS(ProposalAction, id)

  struct Vote : public ProposalAction
  {
    Script ballot;
  };
  DECLARE_JSON_TYPE_WITH_BASE(Vote, ProposalAction)
  DECLARE_JSON_REQUIRED_FIELDS(Vote, ballot)

  //! A call proposed by a proposal script
  struct ProposedCall
  {
    //! the name of the function to call
    std::string func;
    //! the corresponding arguments
    nlohmann::json args;
  };
  DECLARE_JSON_TYPE(ProposedCall)
  DECLARE_JSON_REQUIRED_FIELDS(ProposedCall, func, args)

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
    }
  }
};
FMT_END_NAMESPACE
