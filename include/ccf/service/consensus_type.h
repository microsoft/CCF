// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

namespace ccf
{
  enum ConsensusType : uint8_t
  {
    CFT = 0,
    BFT = 1
  };

  DECLARE_JSON_ENUM(
    ConsensusType, {{ConsensusType::CFT, "CFT"}, {ConsensusType::BFT, "BFT"}})
}
