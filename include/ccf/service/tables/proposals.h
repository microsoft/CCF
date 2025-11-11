// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/map.h"

#include <unordered_map>
#include <vector>

namespace ccf
{
  /** Members use proposals to propose changes to the public governance tables
   * in the KV store. Active members can issue proposals. These proposals are
   * stored in the KV, and passed to the JS constitution functions for
   * validation and execution.
   */
  enum class ProposalState : uint8_t
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

  using ProposalId = std::string;
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::ProposalState>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::ProposalState& state, FormatContext& ctx) const
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
