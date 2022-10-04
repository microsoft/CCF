// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

#include <vector>

namespace ccf
{
  class AbstractRPCResponder : public ccf::AbstractNodeSubSystem
  {
  public:
    virtual ~AbstractRPCResponder() = default;

    static char const* get_subsystem_name()
    {
      return "RPCResponder";
    }

    virtual bool reply_async(int64_t connection_id, std::vector<uint8_t>&& data) = 0;
    virtual bool reply_async(int64_t connection_id, size_t status_code, std::vector<uint8_t>&& data) = 0;
    // TODO: Add reply_async_structured, taking unserialised response description
  };
}