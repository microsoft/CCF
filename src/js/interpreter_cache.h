// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./interpreter_cache_interface.h"

namespace ccf::js
{
  class InterpreterCache : public AbstractInterpreterCache
  {
  protected:
    // TODO: Thread safety
    std::map<std::string, std::shared_ptr<js::Context>> cache;
    size_t cache_build_marker;

  public:
    std::shared_ptr<js::Context> get_interpreter(
      js::TxAccess access,
      const JSDynamicEndpoint& endpoint,
      size_t freshness_marker) override
    {
      if (access != js::TxAccess::APP)
      {
        throw std::logic_error(
          "JS interpreter reuse cache is currently only supported for APP "
          "interpreters");
      }

      if (cache_build_marker != freshness_marker)
      {
        LOG_INFO_FMT(
          "Clearing interpreter cache at {} - rebuilding at {}",
          cache_build_marker,
          freshness_marker);
        cache.clear();
        cache_build_marker = freshness_marker;
      }

      if (endpoint.properties.global_reuse.has_value())
      {
        switch (endpoint.properties.global_reuse->kind)
        {
          case ccf::endpoints::GlobalReusePolicy::KeyBased:
          {
            const auto key = endpoint.properties.global_reuse->key;
            auto it = cache.find(key);
            if (it == cache.end())
            {
              it = cache.emplace_hint(
                it, key, std::make_shared<js::Context>(access));
            }
            return it->second;
          }
        }
      }

      // Return a fresh interpreter, not stored in the cache
      return std::make_shared<js::Context>(access);
    }
    
    void set_max_cached_interpreters(size_t max) override {

    }
  };
}
