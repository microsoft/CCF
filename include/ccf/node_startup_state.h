// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

namespace ccf
{
  enum class NodeStartupState : uint8_t
  {
    uninitialized,
    initialized,
    pending,
    partOfPublicNetwork,
    partOfNetwork,
    readingPublicLedger,
    readingPrivateLedger
  };

  DECLARE_JSON_ENUM(
    ccf::NodeStartupState,
    {{ccf::NodeStartupState::uninitialized, "Uninitialized"},
     {ccf::NodeStartupState::initialized, "Initialized"},
     {ccf::NodeStartupState::pending, "Pending"},
     {ccf::NodeStartupState::partOfPublicNetwork, "PartOfPublicNetwork"},
     {ccf::NodeStartupState::partOfNetwork, "PartOfNetwork"},
     {ccf::NodeStartupState::readingPublicLedger, "ReadingPublicLedger"},
     {ccf::NodeStartupState::readingPrivateLedger, "ReadingPrivateLedger"}});
}

// Used by fmtlib to render ccf::State
// NOLINTBEGIN(cert-dcl58-cpp)
namespace std
{
  inline std::ostream& operator<<(std::ostream& os, ccf::NodeStartupState s)
  {
    nlohmann::json j;
    to_json(j, s);
    return os << j.dump();
  }
}
// NOLINTEND(cert-dcl58-cpp)