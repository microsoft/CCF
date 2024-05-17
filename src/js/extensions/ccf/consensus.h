// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  class CcfConsensusExtension : public ExtensionInterface
  {
  public:
    ccf::BaseEndpointRegistry* endpoint_registry;

    CcfConsensusExtension(ccf::BaseEndpointRegistry* er) : endpoint_registry(er)
    {}

    void install(js::core::Context& ctx) override;
  };
}
