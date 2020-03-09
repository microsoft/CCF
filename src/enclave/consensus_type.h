// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

enum ConsensusType
{
  RAFT = 0,
  PBFT = 1
};

DECLARE_JSON_ENUM(
  ConsensusType,
  {{ConsensusType::RAFT, "RAFT"}, {ConsensusType::PBFT, "PBFT"}});

MSGPACK_ADD_ENUM(ConsensusType);
