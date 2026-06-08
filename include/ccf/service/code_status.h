// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/ds/json.h"
#include "ccf/pal/measurement.h"

namespace ccf
{
  enum class CodeStatus
  {
    ALLOWED_TO_JOIN = 0
  };
  DECLARE_JSON_ENUM(
    CodeStatus, {{CodeStatus::ALLOWED_TO_JOIN, "AllowedToJoin"}});
}