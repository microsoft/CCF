// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint.h"
#include "ccf/js/tx_access.h"
#include "ccf/node_subsystem_interface.h"

namespace ccf::js
{
  namespace core
  {
    class Context;
  };

  struct JSDynamicEndpoint : public ccf::endpoints::EndpointDefinition
  {};

  using InterpreterFactory =
    std::function<std::shared_ptr<js::core::Context>(js::TxAccess)>;

  class AbstractInterpreterCache : public ccf::AbstractNodeSubSystem
  {
  public:
    ~AbstractInterpreterCache() override = default;

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
      const std::optional<ccf::endpoints::InterpreterReusePolicy>&
        interpreter_reuse,
      size_t freshness_marker) = 0;

    // Cap the total number of interpreters which will be retained. The
    // underlying cache functions as an LRU, evicting the interpreter which has
    // been idle the longest when the cap is reached.
    virtual void set_max_cached_interpreters(size_t max) = 0;

    virtual void set_interpreter_factory(const InterpreterFactory& ip) = 0;
  };
}
