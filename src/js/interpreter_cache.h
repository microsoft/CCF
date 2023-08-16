// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./interpreter_cache_interface.h"
#include "ccf/pal/locking.h"
#include "ds/lru.h"

namespace ccf::js
{
  class InterpreterCache : public AbstractInterpreterCache
  {
  protected:
    // Locks access to all internal fields
    ccf::pal::Mutex lock;
    LRU<std::string, std::shared_ptr<js::Context>> lru;
    size_t cache_build_marker;

  public:
    InterpreterCache() : lru(10) {}

    std::shared_ptr<js::Context> get_interpreter(
      js::TxAccess access,
      const JSDynamicEndpoint& endpoint,
      size_t freshness_marker) override
    {
      if (access != js::TxAccess::APP)
      {
        throw std::logic_error(
          "JS interpreter reuse lru is currently only supported for APP "
          "interpreters");
      }

      std::lock_guard<ccf::pal::Mutex> guard(lock);

      if (cache_build_marker != freshness_marker)
      {
        LOG_INFO_FMT(
          "Clearing interpreter lru at {} - rebuilding at {}",
          cache_build_marker,
          freshness_marker);
        lru.clear();
        cache_build_marker = freshness_marker;
      }

      if (endpoint.properties.global_reuse.has_value())
      {
        switch (endpoint.properties.global_reuse->kind)
        {
          case ccf::endpoints::GlobalReusePolicy::KeyBased:
          {
            const auto key = endpoint.properties.global_reuse->key;
            return lru[key];
          }
        }
      }

      // Return a fresh interpreter, not stored in the cache
      return std::make_shared<js::Context>(access);
    }

    void set_max_cached_interpreters(size_t max) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      lru.set_max_size(max);
    }
  };
}
