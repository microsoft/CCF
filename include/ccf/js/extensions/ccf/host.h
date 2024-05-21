// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"
#include "ccf/node/host_processes_interface.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - ccf.host.triggerSubprocess
   *
   **/
  class HostExtension : public ExtensionInterface
  {
  public:
    ccf::AbstractHostProcesses* host_processes;

    HostExtension(ccf::AbstractHostProcesses* hp) : host_processes(hp) {}

    void install(js::core::Context& ctx) override;
  };
}
