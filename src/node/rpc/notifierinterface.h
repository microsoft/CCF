// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdint.h>
#include <vector>

namespace ccf
{
  class AbstractNotifier
  {
  public:
    virtual ~AbstractNotifier() {}
    virtual void notify(const std::vector<uint8_t>& data) = 0;
  };
}