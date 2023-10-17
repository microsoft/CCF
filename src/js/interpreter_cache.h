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
    InterpreterCache(size_t max_cache_size) : lru(max_cache_size) {}

    std::shared_ptr<js::Context> get_interpreter(
      js::TxAccess access,
      const JSDynamicEndpoint& endpoint,
      size_t freshness_marker) override
    {
      if (access != js::TxAccess::APP)
      {
        throw std::logic_error(
          "JS interpreter reuse lru is only supported for APP "
          "interpreters");
      }

      // Return a fresh interpreter every time, the re-use of interpreters
      // is not enabled on 4.x
      LOG_TRACE_FMT("Returning freshly constructed interpreter");
      return std::make_shared<js::Context>(access);
    }

    void set_max_cached_interpreters(size_t max) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      lru.set_max_size(max);
    }
  };
}
