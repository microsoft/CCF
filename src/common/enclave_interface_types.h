// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

enum CreateNodeStatus
{
  OK = 0,
  InternalError = 1,
  NodeAlreadyCreated = 2,
  ConsensusNotAllowed = 3,
  TooManyThreads = 4,
  MemoryNotInEnclave = 5,
};

constexpr char const* create_node_result_to_str(CreateNodeStatus result)
{
  switch (result)
  {
    case CreateNodeStatus::OK:
    {
      return "OK";
    }
    case CreateNodeStatus::InternalError:
    {
      return "InternalError";
    }
    case CreateNodeStatus::NodeAlreadyCreated:
    {
      return "NodeAlreadyCreated";
    }
    case CreateNodeStatus::ConsensusNotAllowed:
    {
      return "ConsensusNotAllowed";
    }
    case CreateNodeStatus::TooManyThreads:
    {
      return "TooManyThreads";
    }
    case CreateNodeStatus::MemoryNotInEnclave:
    {
      return "MemoryNodeInEnclave";
    }
    default:
    {
      return "Unknown CreateNodeStatus";
    }
  }
}

enum StartType
{
  New = 1,
  Join = 2,
  Recover = 3,
};