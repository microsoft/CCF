// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/host_processes_interface.h"
#include "js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  class CcfHostExtension : public ExtensionInterface
  {
  public:
    ccf::AbstractHostProcesses* host_processes;

    CcfHostExtension(ccf::AbstractHostProcesses* hp) : host_processes(hp) {}

    void install(js::core::Context& ctx) override;
  };
}
