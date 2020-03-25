// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"

#include <msgpack/msgpack.hpp>

namespace ccf
{
  enum class CodeStatus
  {
    ACCEPTED = 0,
    RETIRED = 1,
  };
  DECLARE_JSON_ENUM(
    CodeStatus,
    {{CodeStatus::ACCEPTED, "ACCEPTED"}, {CodeStatus::RETIRED, "RETIRED"}});
}

MSGPACK_ADD_ENUM(ccf::CodeStatus);

namespace ccf
{
  using CodeIDs = Store::Map<CodeDigest, CodeStatus>;
}
