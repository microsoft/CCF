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

  public:
    SigtermImpl(ringbuffer::AbstractWriterFactory& writer_factory) :
      to_enclave(writer_factory.create_writer_to_inside())
    {}

    void on_signal()
    {
      LOG_INFO_FMT("SIGTERM: Shutting down enclave gracefully...");
      RINGBUFFER_WRITE_MESSAGE(AdminMessage::stop, to_enclave);
      uv_stop(uv_default_loop());
    }
  };

  using Sigterm = proxy_ptr<Signal<SIGTERM, SigtermImpl>>;
}
