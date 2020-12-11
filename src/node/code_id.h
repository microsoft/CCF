// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"
#include "kv/map.h"

#include <msgpack/msgpack.hpp>

namespace ccf
{
  enum class CodeStatus
  {
    ALLOWED_TO_JOIN = 0
  };
  DECLARE_JSON_ENUM(
    CodeStatus, {{CodeStatus::ALLOWED_TO_JOIN, "ALLOWED_TO_JOIN"}});
}

MSGPACK_ADD_ENUM(ccf::CodeStatus);

namespace ccf
{
  using CodeIDs = kv::Map<CodeDigest, CodeStatus>;
}
