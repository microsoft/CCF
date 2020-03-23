// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"

#include <msgpack/msgpack.hpp>

namespace ccf
{
  using ConsensusTable = Store::Map<ObjectId, ConsensusType>;
}

DECLARE_JSON_ENUM(
  ConsensusType, {{ConsensusType::RAFT, "RAFT"}, {ConsensusType::PBFT, "PBFT"}})

MSGPACK_ADD_ENUM(ConsensusType);
