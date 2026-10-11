// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/json.h"
#include "common/enclave_interface_types.h"

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
