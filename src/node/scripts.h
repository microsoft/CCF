// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"
#include "script.h"

namespace ccf
{
  using Scripts = Store::Map<std::string, Script>;

  struct GovScriptIds
  {
    //! script that decides if the required quorum for a proposal
    static auto constexpr QUORUM = "quorum";
    //! script that applies an accepted "raw puts" proposal
    static auto constexpr RAW_PUTS = "raw_puts";
    //! script that sets the environment for a proposal script
    static auto constexpr ENV_PROPOSAL = "environment_proposal";
  };

  struct UserScriptIds
  {
    //! default script for handling rpc
    static auto constexpr DEFAULT_HANDLER = "__default";
    //! script that sets the environment for rpc handler scripts
    static auto constexpr ENV_HANDLER = "__environment";
  };
}