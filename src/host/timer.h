// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "proxy.h"

#include <chrono>

namespace asynchost
{
  template <typename Behaviour>
  class Timer : public with_uv_handle<uv_timer_t>
  {
  private:
    friend class close_ptr<Timer<Behaviour>>;
    Behaviour behaviour;

    template <typename... Args>
    Timer(uint64_t repeat_ms, Args&&... args) :
      behaviour(std::forward<Args>(args)...)
    {
      int rc;

      if ((rc = uv_timer_init(uv_default_loop(), &uv_handle)) < 0)
      {
        LOG_FAIL << "uv_timer_init failed: " << uv_strerror(rc) << std::endl;
        throw std::logic_error("uv_timer_init failed");
      }

      uv_handle.data = this;

      if ((rc = uv_timer_start(&uv_handle, on_timer, 0, repeat_ms)) < 0)
      {
        LOG_FAIL << "uv_timer_start failed: " << uv_strerror(rc) << std::endl;
        throw std::logic_error("uv_timer_start failed");
      }
    }

    static void on_timer(uv_timer_t* handle)
    {
      static_cast<Timer*>(handle->data)->on_timer();
    }

    void on_timer()
    {
      behaviour.on_timer();
    }
  };
}
