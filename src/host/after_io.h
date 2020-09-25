// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "proxy.h"

namespace asynchost
{
  template <typename Behaviour>
  class AfterIO : public with_uv_handle<uv_check_t>
  {
  private:
    friend class close_ptr<AfterIO<Behaviour>>;
    Behaviour behaviour;

    template <typename... Args>
    AfterIO(Args&&... args) : behaviour(std::forward<Args>(args)...)
    {
      int rc;

      if ((rc = uv_check_init(uv_default_loop(), &uv_handle)) < 0)
      {
        LOG_FAIL_FMT("uv_check_init failed: {}", uv_strerror(rc));
        throw std::logic_error("uv_check_init failed");
      }

      uv_handle.data = this;

      if ((rc = uv_check_start(&uv_handle, on_check)) < 0)
      {
        LOG_FAIL_FMT("uv_check_start failed: {}", uv_strerror(rc));
        throw std::logic_error("uv_check_start failed");
      }
    }

    static void on_check(uv_check_t* handle)
    {
      static_cast<AfterIO*>(handle->data)->on_check();
    }

    void on_check()
    {
      behaviour.after_io();
    }
  };
}
