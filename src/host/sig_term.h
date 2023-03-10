// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave.h"
#include "signal.h"

#include <chrono>

namespace asynchost
{
  class SigtermImpl
  {
  private:
    ringbuffer::WriterPtr to_enclave;
    bool ignore_first_sigterm = false;
    size_t sigterm_count = 0;

  public:
    SigtermImpl(
      ringbuffer::AbstractWriterFactory& writer_factory,
      bool ignore_first_sigterm_) :
      to_enclave(writer_factory.create_writer_to_inside()),
      ignore_first_sigterm(ignore_first_sigterm_)
    {}

    void on_signal()
    {
      sigterm_count++;
      if (ignore_first_sigterm && sigterm_count <= 1)
      {
        LOG_INFO_FMT("SIGTERM: Notifying enclave, but not shutting down.");
        RINGBUFFER_WRITE_MESSAGE(AdminMessage::stop_notice, to_enclave);
      }
      else
      {
        LOG_INFO_FMT("SIGTERM: Shutting down enclave gracefully...");
        RINGBUFFER_WRITE_MESSAGE(AdminMessage::stop, to_enclave);
      }
    }
  };

  using Sigterm = proxy_ptr<Signal<SIGTERM, SigtermImpl>>;
}
