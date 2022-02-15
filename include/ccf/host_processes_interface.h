// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>
#include <vector>

namespace ccf
{
  class AbstractHostProcesses
  {
  public:
    virtual ~AbstractHostProcesses() = default;

    virtual void trigger_host_process_launch(
      const std::vector<std::string>& args) = 0;
  };
}
