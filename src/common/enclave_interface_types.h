// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger_level.h"

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

  /** Enclave initialisation failed */
  EnclaveInitFailed = 6,

  /** OpenSSL RDRAND Init Failed */
  OpenSSLRDRANDInitFailed = 7,

  /** The reconfiguration method is not supported */
  ReconfigurationMethodNotSupported = 8,

  /** Host and enclave versions must match */
  VersionMismatch = 9,

  /** When reading from host memory, the source must be 8-byte aligned **/
  UnalignedArguments = 10,
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
    case CreateNodeStatus::EnclaveInitFailed:
    {
      return "EnclaveInitFailed";
    }
    case CreateNodeStatus::OpenSSLRDRANDInitFailed:
    {
      return "OpenSSLRDRANDInitFailed";
    }
    case CreateNodeStatus::ReconfigurationMethodNotSupported:
    {
      return "ReconfigurationMethodNotSupported";
    }
    case CreateNodeStatus::VersionMismatch:
    {
      return "VersionMismatch";
    }
    case CreateNodeStatus::UnalignedArguments:
    {
      return "UnalignedArguments";
    }
    default:
    {
      return "Unknown CreateNodeStatus";
    }
  }
}

enum StartType
{
  Start = 1,
  Join = 2,
  Recover = 3,
};

constexpr char const* start_type_to_str(StartType type)
{
  switch (type)
  {
    case StartType::Start:
      return "Start";
    case StartType::Join:
      return "Join";
    case StartType::Recover:
      return "Recover";
    default:
      return "Unknown StartType";
  }
}