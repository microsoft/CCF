// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

enum CreateNodeStatus
{
  /** Call was successful and the node was successfully created */
  OK = 0,

  /** The node could not be created because of an internal error */
  InternalError = 1,

  /** The node has already been created */
  NodeAlreadyCreated = 2,

  /** The selected consensus is not valid */
  ConsensusNotAllowed = 3,

  /** The number of worker threads created is too high */
  TooManyThreads = 4,

  /** One of the input buffers is not located outside of the enclave memory */
  MemoryNotOutsideEnclave = 5,
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
    case CreateNodeStatus::MemoryNotOutsideEnclave:
    {
      return "MemoryNotOutsideEnclave";
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