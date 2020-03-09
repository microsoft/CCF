// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"

#include <msgpack.hpp>

namespace ccf
{
  struct Consensus
  {
    ConsensusType consensus_type;

    MSGPACK_DEFINE(consensus_type);
  };

 DECLARE_JSON_REQUIRED_FIELDS(Consensus, consensus_type)
 using ConsensusTable = Store::Map<ObjectId, Consensus>;
}