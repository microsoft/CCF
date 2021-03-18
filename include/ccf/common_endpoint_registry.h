// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"

namespace ccf
{
  /*
   * Extends the BaseEndpointRegistry by installing common endpoints we expect
   * to be available on most services. Override init_handlers or inherit from
   * BaseEndpointRegistry directly if you wish to wrap some of this
   * functionality in different Endpoints.
   */
  class CommonEndpointRegistry : public BaseEndpointRegistry
  {
  public:
    CommonEndpointRegistry(
      const std::string& method_prefix_, ccfapp::AbstractNodeContext& context_);

    void init_handlers() override;
  };
}
