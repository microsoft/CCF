// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/consensus_type.h"

DECLARE_JSON_ENUM(
  ConsensusType, {{ConsensusType::CFT, "CFT"}, {ConsensusType::BFT, "BFT"}})
