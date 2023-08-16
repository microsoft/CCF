// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./wrap.h"
#include "ccf/endpoint.h"
#include "ccf/node_subsystem_interface.h"

namespace ccf::js
{
  struct JSDynamicEndpoint : public ccf::endpoints::EndpointDefinition
  {};

  class AbstractInterpreterCache : public ccf::AbstractNodeSubSystem
  {
  public:
    virtual ~AbstractInterpreterCache() = default;

    static char const* get_subsystem_name()
    {
      return "InterpreterCache";
    }

    // TODO: Docs
    virtual std::shared_ptr<js::Context> get_interpreter(
      js::TxAccess access,
      const JSDynamicEndpoint& endpoint,
      size_t freshness_marker) = 0;

    virtual void set_max_cached_interpreters(size_t max) = 0;
  };
}
