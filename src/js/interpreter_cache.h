// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./interpreter_cache_interface.h"

namespace ccf::js
{
  class InterpreterCache : public AbstractInterpreterCache
  {
  protected:
    struct TODO
    {};
    std::map<TODO, std::shared_ptr<js::Context>> cached;

  public:
    std::shared_ptr<js::Context> get_interpreter(
      js::TxAccess access, const JSDynamicEndpoint& endpoint) override
    {
      if (access != js::TxAccess::APP)
      {
        throw std::logic_error(
          "JS interpreter reuse cache is currently only supported for APP "
          "interpreters");
      }

      // Return a new interpreter, not stored in the cache
      return std::make_shared<js::Context>(access);
    }
  };
}
