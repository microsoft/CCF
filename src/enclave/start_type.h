// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

enum CreateNodeStatus
{
  OK = 0,
  InternalError = 1,
  NodeAlreadyCreated = 2,
  VersionMismatch = 3,
  ConsensusNotAllowed = 4,
  TooManyThreads = 5,
  MemoryNotInEnclave = 6,
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
    case CreateNodeStatus::VersionMismatch:
    {
      return "VersionMismatch";
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
  Unknown = 100
};