// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint.h"
#include "ccf/node_subsystem_interface.h"
#include "js/tx_access.h"

namespace ccf::js
{
  namespace core
  {
    class Context;
  };

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

    // Retrieve an interpreter, based on reuse policy specified in the endpoint.
    // Note that in some cases, notably if the reuse policy does not permit
    // reuse, this will actually return a freshly-constructed, non-cached
    // interpreter. The caller should not care whether the returned value is
    // fresh or previously used, and should treat it identically going forward.
    // The only benefit of a reused value from the cache should be seen during
    // execution, where some global initialisation may already be done.
    virtual std::shared_ptr<js::core::Context> get_interpreter(
      js::TxAccess access,
      const JSDynamicEndpoint& endpoint,
      size_t freshness_marker) = 0;

    // Cap the total number of interpreters which will be retained. The
    // underlying cache functions as an LRU, evicting the interpreter which has
    // been idle the longest when the cap is reached.
    virtual void set_max_cached_interpreters(size_t max) = 0;
  };
}
