// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "signal.h"

#include <chrono>
#include <cstring>
#include <functional>

namespace asynchost
{
  class ShutdownSignalImpl
  {
  private:
    bool ignore_first_signal = false;
    size_t signal_count = 0;
    std::function<void()> request_stop;
    std::function<void()> request_stop_notice;

  public:
    ShutdownSignalImpl(
      bool ignore_first_sigterm_,
      std::function<void()> request_stop_,
      std::function<void()> request_stop_notice_) :
      ignore_first_signal(ignore_first_sigterm_),
      request_stop(std::move(request_stop_)),
      request_stop_notice(std::move(request_stop_notice_))
    {}

    void on_signal(int signal)
    {
      signal_count++;
      if (ignore_first_signal && signal_count <= 1)
      {
        LOG_INFO_FMT(
          "SIG{}: Notifying enclave, but not shutting down.",
          sigabbrev_np(signal));
        request_stop_notice();
      }
      else
      {
        LOG_INFO_FMT(
          "SIG{}: Shutting down enclave gracefully...", sigabbrev_np(signal));
        request_stop();
      }
    }
  };

  using Sigterm = ccf::uv::proxy_ptr<Signal<SIGTERM, ShutdownSignalImpl>>;
  using Sighup = ccf::uv::proxy_ptr<Signal<SIGHUP, ShutdownSignalImpl>>;
}
