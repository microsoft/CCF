// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./interpreter_cache_interface.h"

namespace ccf::js
{
  class InterpreterCache : public AbstractInterpreterCache
  {
  protected:
    std::map<std::string, std::shared_ptr<js::Context>> cached;

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

      if (endpoint.properties.global_reuse.has_value())
      {
        switch (endpoint.properties.global_reuse->kind)
        {
          case ccf::endpoints::GlobalReusePolicy::KeyBased:
          {
            const auto key = endpoint.properties.global_reuse->key;
            auto it = cached.find(key);
            if (it == cached.end())
            {
              it = cached.emplace_hint(
                it, key, std::make_shared<js::Context>(access));
            }
            // TODO: But what if it's out-of-date?
            return it->second;
          }
        }
      }

      // Return a fresh interpreter, not stored in the cache
      return std::make_shared<js::Context>(access);
    }
  };
}
