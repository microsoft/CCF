// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

#include <vector>

namespace ccf
{
  // TODO: Collide with http_responder?
  class AbstractRPCResponder : public ccf::AbstractNodeSubSystem
  {
  public:
    virtual ~AbstractRPCResponder() = default;

    static char const* get_subsystem_name()
    {
      return "RPCResponder";
    }

    virtual bool reply_async(
      int64_t connection_id, std::vector<uint8_t>&& data) = 0;
    virtual bool reply_async(
      int64_t connection_id,
      int32_t stream_id,
      size_t status_code,
      std::vector<uint8_t>&& data) = 0;
  };
}