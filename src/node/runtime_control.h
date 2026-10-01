// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>

namespace ccf
{
  class AbstractRuntimeControl
  {
  public:
    virtual ~AbstractRuntimeControl() = default;

    virtual void report_stopped() = 0;
    virtual void report_fatal_error(const std::string& message) = 0;
    virtual void request_restart() = 0;
  };
}
