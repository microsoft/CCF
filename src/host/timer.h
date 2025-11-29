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
  public:
    Behaviour behaviour;

  private:
    friend class close_ptr<Timer<Behaviour>>;

    template <typename... Args>
    Timer(std::chrono::milliseconds repeat_ms, Args&&... args) :
      behaviour(std::forward<Args>(args)...)
    {
      int rc = 0;

      if ((rc = uv_timer_init(uv_default_loop(), &uv_handle)) < 0)
      {
        LOG_FAIL_FMT("uv_timer_init failed: {}", uv_strerror(rc));
        throw std::logic_error("uv_timer_init failed");
      }

      uv_handle.data = this;

      if ((rc = uv_timer_start(&uv_handle, on_timer, 0, repeat_ms.count())) < 0)
      {
        LOG_FAIL_FMT("uv_timer_start failed: {}", uv_strerror(rc));
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
