// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "proxy.h"

namespace asynchost
{
  // This runs every loop. If any instance of this is active, the loop's poll
  // timeout will be 0 (see uv_prepare_t vs uv_idle_t)
  template <typename Behaviour>
  class EveryIO : public with_uv_handle<uv_idle_t>
  {
  private:
    friend class close_ptr<EveryIO<Behaviour>>;
    Behaviour behaviour;

    template <typename... Args>
    EveryIO(Args&&... args) : behaviour(std::forward<Args>(args)...)
    {
      int rc;

      if ((rc = uv_idle_init(uv_default_loop(), &uv_handle)) < 0)
      {
        LOG_FAIL_FMT("uv_idle_init failed: {}", uv_strerror(rc));
        throw std::logic_error("uv_idle_init failed");
      }

      uv_handle.data = this;

      if ((rc = uv_idle_start(&uv_handle, on_every)) < 0)
      {
        LOG_FAIL_FMT("uv_idle_start failed: {}", uv_strerror(rc));
        throw std::logic_error("uv_idle_start failed");
      }
    }

    static void on_every(uv_idle_t* handle)
    {
      static_cast<EveryIO*>(handle->data)->on_every();
    }

    void on_every()
    {
      behaviour.every();
    }
  };
}
