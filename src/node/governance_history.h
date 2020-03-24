// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"
#include "script.h"

#include <msgpack/msgpack.hpp>
#include <unordered_map>
#include <vector>

namespace ccf
{
  struct GovernanceHistoryEntry
  {
    SignedReq signed_request;
    MSGPACK_DEFINE(signed_request);
  };
  DECLARE_JSON_TYPE(GovernanceHistoryEntry)
  DECLARE_JSON_REQUIRED_FIELDS(GovernanceHistoryEntry, signed_request)
  using GovernanceHistory = Store::Map<MemberId, GovernanceHistoryEntry>;
}
