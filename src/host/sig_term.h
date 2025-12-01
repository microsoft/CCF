// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "signal.h"

#include <chrono>
#include <cstring>

namespace asynchost
{
  class ShutdownSignalImpl
  {
  private:
    ringbuffer::WriterPtr to_enclave;
    bool ignore_first_signal = false;
    size_t signal_count = 0;

  public:
    ShutdownSignalImpl(
      ringbuffer::AbstractWriterFactory& writer_factory,
      bool ignore_first_sigterm_) :
      to_enclave(writer_factory.create_writer_to_inside()),
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
        RINGBUFFER_WRITE_MESSAGE(AdminMessage::stop_notice, to_enclave);
      }
      else
      {
        LOG_INFO_FMT(
          "SIG{}: Shutting down enclave gracefully...", sigabbrev_np(signal));
        RINGBUFFER_WRITE_MESSAGE(AdminMessage::stop, to_enclave);
      }
    }
  };

  using Sigterm = proxy_ptr<Signal<SIGTERM, ShutdownSignalImpl>>;
  using Sighup = proxy_ptr<Signal<SIGHUP, ShutdownSignalImpl>>;
}
