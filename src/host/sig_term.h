// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/entry_points.h"
#include "signal.h"

#include <chrono>
#include <cstring>

namespace asynchost
{
  class ShutdownSignalImpl
  {
  private:
    bool ignore_first_signal = false;
    size_t signal_count = 0;

  public:
    ShutdownSignalImpl(bool ignore_first_sigterm_) :
      ignore_first_signal(ignore_first_sigterm_)
    {}

    void on_signal(int signal)
    {
      signal_count++;
      if (ignore_first_signal && signal_count <= 1)
      {
        LOG_INFO_FMT(
          "SIG{}: Notifying enclave, but not shutting down.",
          sigabbrev_np(signal));
        if (!ccf::enclave_request_stop_notice())
        {
          LOG_FAIL_FMT("Failed to request enclave stop notice");
        }
      }
      else
      {
        LOG_INFO_FMT(
          "SIG{}: Shutting down enclave gracefully...", sigabbrev_np(signal));
        if (!ccf::enclave_request_stop())
        {
          LOG_FAIL_FMT("Failed to request enclave stop");
        }
      }
    }
  };

  using Sigterm = ccf::uv::proxy_ptr<Signal<SIGTERM, ShutdownSignalImpl>>;
  using Sighup = ccf::uv::proxy_ptr<Signal<SIGHUP, ShutdownSignalImpl>>;
}
