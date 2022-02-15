// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

#include <string>
#include <vector>

// TODO: Doesn't need to be public!
namespace ccf
{
  class AbstractHostProcesses : public ccf::AbstractNodeSubSystem
  {
  public:
    virtual ~AbstractHostProcesses() = default;

    static char const* get_subsystem_name()
    {
      return "HostProcesses";
    }

    virtual void trigger_host_process_launch(
      const std::vector<std::string>& args) = 0;
  };
}
