// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"
#include "kv/map.h"

namespace ccf
{
  using ConsensusTable = kv::Map<ObjectId, ConsensusType>;
}
