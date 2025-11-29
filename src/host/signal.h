// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "proxy.h"

#include <chrono>

namespace asynchost
{
  template <int signum, typename Behaviour>
  class Signal : public with_uv_handle<uv_signal_t>
  {
  private:
    friend class close_ptr<Signal<signum, Behaviour>>;
    Behaviour behaviour;

    template <typename... Args>
    Signal(Args&&... args) : behaviour(std::forward<Args>(args)...)
    {
      int rc = 0;

      if ((rc = uv_signal_init(uv_default_loop(), &uv_handle)) < 0)
      {
        LOG_FAIL_FMT("uv_signal_init failed: {}", uv_strerror(rc));
        throw std::logic_error("uv_signal_init failed");
      }

      uv_handle.data = this;

      if ((rc = uv_signal_start(&uv_handle, on_signal, signum)) < 0)
      {
        LOG_FAIL_FMT("uv_signal_start failed: {}", uv_strerror(rc));
        throw std::logic_error("uv_signal_start failed");
      }
    }

    static void on_signal(uv_signal_t* handle, int signal)
    {
      static_cast<Signal*>(handle->data)->on_signal(signal);
    }

    void on_signal(int signal)
    {
      behaviour.on_signal(signal);
      uv_signal_stop(&uv_handle);
    }
  };
}
