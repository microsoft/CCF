// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/json.h"
#include "common/enclave_interface_types.h"
#include "ds/oversized.h"

struct EnclaveConfig
{
  uint8_t* to_enclave_buffer_start = nullptr;
  size_t to_enclave_buffer_size = 0;
  ringbuffer::Offsets* to_enclave_buffer_offsets = nullptr;

  uint8_t* from_enclave_buffer_start = nullptr;
  size_t from_enclave_buffer_size = 0;
  ringbuffer::Offsets* from_enclave_buffer_offsets = nullptr;

  oversized::WriterConfig writer_config = {};
};

static constexpr auto node_to_node_interface_name = "node_to_node_interface";

namespace ccf
{
  DECLARE_JSON_ENUM(
    LoggerLevel,
    {{LoggerLevel::TRACE, "Trace"},
     {LoggerLevel::DEBUG, "Debug"},
     {LoggerLevel::INFO, "Info"},
     {LoggerLevel::FAIL, "Fail"},
     {LoggerLevel::FATAL, "Fatal"}});
}
