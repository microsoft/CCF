// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <limits>

namespace aft
{
  class IMessage
  {
  public:
    IMessage() = default;
    virtual ~IMessage() = default;

    virtual bool should_encrypt() const = 0;
    virtual void serialize_message(
      aft::NodeId from_node, uint8_t* data, size_t size) const = 0;
    virtual size_t size() const = 0;
  };
}