// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
#include "enclave/runtime_control.h"
#include "uv/proxy.h"

#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>

namespace asynchost
{
  class RuntimeControlImpl : public ccf::uv::with_uv_handle<uv_async_t>,
                             public ccf::AbstractRuntimeControl
  {
  private:
    friend class ccf::uv::close_ptr<RuntimeControlImpl>;

    std::function<bool()> stop_enclave;
    std::function<void()> before_loop_stop;
    std::mutex mutex;
    std::optional<std::string> fatal_error;

    static void on_wake(uv_async_t* handle)
    {
      auto* self = static_cast<RuntimeControlImpl*>(handle->data);
      self->before_loop_stop();
      uv_stop(handle->loop);
    }

    void wake_and_stop_loop()
    {
      const auto rc = uv_async_send(&uv_handle);
      if (rc != 0)
      {
        LOG_FAIL_FMT(
          "Failed to wake host loop for shutdown: {}", uv_strerror(rc));
      }
    }

    bool stop_enclave_or_log()
    {
      if (!stop_enclave())
      {
        LOG_FAIL_FMT("Cannot stop enclave before it has been created");
        return false;
      }
      return true;
    }

    RuntimeControlImpl(
      std::function<bool()> stop_enclave_,
      std::function<void()> before_loop_stop_) :
      stop_enclave(std::move(stop_enclave_)),
      before_loop_stop(std::move(before_loop_stop_))
    {
      const auto rc = uv_async_init(uv_default_loop(), &uv_handle, on_wake);
      if (rc != 0)
      {
        throw std::logic_error(
          fmt::format("uv_async_init failed: {}", uv_strerror(rc)));
      }
      uv_handle.data = this;
    }

  public:
    void report_stopped() override
    {
      LOG_INFO_FMT("Host stopped successfully");
      wake_and_stop_loop();
    }

    void report_fatal_error(const std::string& message) override
    {
      {
        std::lock_guard<std::mutex> guard(mutex);
        if (!fatal_error.has_value())
        {
          fatal_error = message;
          std::cerr << message << std::endl << std::flush;
        }
      }

      stop_enclave_or_log();
    }

    void request_restart() override
    {
      LOG_INFO_FMT("Received request to restart enclave, stopping enclave");
      stop_enclave_or_log();
    }

    void throw_if_fatal_error()
    {
      std::optional<std::string> error;
      {
        std::lock_guard<std::mutex> guard(mutex);
        error = fatal_error;
      }

      if (error.has_value())
      {
        throw std::logic_error(error.value());
      }
    }
  };

  using RuntimeControl = ccf::uv::proxy_ptr<RuntimeControlImpl>;
}
