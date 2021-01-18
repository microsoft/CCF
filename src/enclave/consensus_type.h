// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

#include <msgpack/msgpack.hpp>

enum ConsensusType
{
  CFT = 0,
  BFT = 1
};

DECLARE_JSON_ENUM(
  ConsensusType, {{ConsensusType::CFT, "CFT"}, {ConsensusType::BFT, "BFT"}})

MSGPACK_ADD_ENUM(ConsensusType);
