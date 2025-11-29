// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
#include "proxy.h"

namespace asynchost
{
  template <typename Behaviour>
  class BeforeIO : public with_uv_handle<uv_prepare_t>
  {
  private:
    friend class close_ptr<BeforeIO<Behaviour>>;
    Behaviour behaviour;

    template <typename... Args>
    BeforeIO(Args&&... args) : behaviour(std::forward<Args>(args)...)
    {
      int rc = 0;

      if ((rc = uv_prepare_init(uv_default_loop(), &uv_handle)) < 0)
      {
        LOG_FAIL_FMT("uv_prepare_init failed: {}", uv_strerror(rc));
        throw std::logic_error("uv_prepare_init failed");
      }

      uv_handle.data = this;

      if ((rc = uv_prepare_start(&uv_handle, on_prepare)) < 0)
      {
        LOG_FAIL_FMT("uv_prepare_start failed: {}", uv_strerror(rc));
        throw std::logic_error("uv_prepare_start failed");
      }
    }

    static void on_prepare(uv_prepare_t* handle)
    {
      static_cast<BeforeIO*>(handle->data)->on_prepare();
    }

    void on_prepare()
    {
      behaviour.before_io();
    }
  };
}
