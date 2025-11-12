// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/interpreter_cache_interface.h"
#include "ccf/pal/locking.h"
#include "ds/lru.h"

namespace ccf::js
{
  class InterpreterCache : public AbstractInterpreterCache
  {
  protected:
    // Locks access to all internal fields
    ccf::pal::Mutex lock;
    LRU<std::string, std::shared_ptr<js::core::Context>> lru;
    size_t cache_build_marker = 0;

    InterpreterFactory interpreter_factory = nullptr;

    std::shared_ptr<js::core::Context> make_interpreter(js::TxAccess access)
    {
      if (interpreter_factory != nullptr)
      {
        return interpreter_factory(access);
      }

      return std::make_shared<js::core::Context>(access);
    }

  public:
    InterpreterCache(size_t max_cache_size) : lru(max_cache_size) {}

    std::shared_ptr<js::core::Context> get_interpreter(
      js::TxAccess access,
      const std::optional<ccf::endpoints::InterpreterReusePolicy>&
        interpreter_reuse,
      size_t freshness_marker) override
    {
      if (access != js::TxAccess::APP_RW && access != js::TxAccess::APP_RO)
      {
        throw std::logic_error(
          "JS interpreter reuse lru is only supported for APP "
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

      if (interpreter_reuse.has_value())
      {
        switch (interpreter_reuse->kind)
        {
          case ccf::endpoints::InterpreterReusePolicy::Kind::KeyBased:
          {
            auto key = interpreter_reuse->key;
            if (access == js::TxAccess::APP_RW)
            {
              key += " (rw)";
            }
            else if (access == js::TxAccess::APP_RO)
            {
              key += " (ro)";
            }
            auto it = lru.find(key);
            if (it == lru.end())
            {
              it = lru.insert(key, make_interpreter(access));
              LOG_INFO_FMT(
                "Constructed cached JS interpreter at key {}. Cache now "
                "contains {} interpreters",
                key,
                lru.size());
            }
            else
            {
              LOG_TRACE_FMT(
                "Returning interpreter previously in cache, with key {}", key);
              lru.promote(it);
            }

            return it->second;
          }
        }
      }

      // Return a fresh interpreter, not stored in the cache
      LOG_TRACE_FMT("Returning freshly constructed interpreter");
      return make_interpreter(access);
    }

    void set_max_cached_interpreters(size_t max) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      lru.set_max_size(max);
    }

    void set_interpreter_factory(const InterpreterFactory& ip) override
    {
      interpreter_factory = ip;
    }
  };
}
