// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"
#include "script.h"

#include <msgpack-c/msgpack.hpp>
#include <unordered_map>
#include <vector>

namespace ccf
{
  struct VotingHistory
  {
    SignedReq signed_request;
    MSGPACK_DEFINE(signed_request);
  };
  ADD_JSON_TRANSLATORS(VotingHistory, signed_request)
  using VotingHistoryTable = Store::Map<MemberId, VotingHistory>;
}
