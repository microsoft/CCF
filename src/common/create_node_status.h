// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>

enum CreateNodeStatus : std::uint8_t
{
  /** Call was successful and the node was successfully created */
  OK = 0,

  /** The node could not be created because of an internal error */
  InternalError = 1,

  /** The node has already been created */
  NodeAlreadyCreated = 2,

  /** Enclave initialisation failed */
  EnclaveInitFailed = 6,

  /** The reconfiguration method is not supported */
  ReconfigurationMethodNotSupported = 8,

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
    case CreateNodeStatus::EnclaveInitFailed:
    {
      return "EnclaveInitFailed";
    }
    case CreateNodeStatus::ReconfigurationMethodNotSupported:
    {
      return "ReconfigurationMethodNotSupported";
    }
    default:
    {
      return "Unknown CreateNodeStatus";
    }
  }
}
