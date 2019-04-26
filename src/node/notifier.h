// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ringbuffer_types.h"
#include "enclave/interface.h"
#include "rpc/frontend.h"

namespace ccf
{
  class Notifier : public ccf::AbstractNotifier
  {
  private:
    std::unique_ptr<ringbuffer::AbstractWriter> to_host;

  public:
    Notifier(ringbuffer::AbstractWriterFactory& writer_factory_) :
      to_host(writer_factory_.create_writer_to_outside())
    {}

    void notify(const std::vector<uint8_t>& data) override
    {
      RINGBUFFER_WRITE_MESSAGE(AdminMessage::notification, to_host, data);
    }
  };
}
