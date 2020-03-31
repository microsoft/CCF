// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/ring_buffer_types.h"
#include "enclave/interface.h"
#include "kv/kv_types.h"
#include "rpc/frontend.h"

namespace ccf
{
  class Notifier : public ccf::AbstractNotifier
  {
  private:
    ringbuffer::WriterPtr to_host;
    std::shared_ptr<kv::Consensus> consensus = nullptr;

  public:
    Notifier(ringbuffer::AbstractWriterFactory& writer_factory_) :
      to_host(writer_factory_.create_writer_to_outside())
    {}

    void notify(const std::vector<uint8_t>& data) override
    {
      if (consensus == nullptr)
      {
        LOG_DEBUG_FMT(
          "Unable to send notification - no consensus has been set");
        return;
      }

      if (consensus->is_primary())
      {
        LOG_DEBUG_FMT("Sending notification");
        RINGBUFFER_WRITE_MESSAGE(AdminMessage::notification, to_host, data);
      }
      else
      {
        LOG_DEBUG_FMT("Ignoring notification - not leader");
      }
    }

    void set_consensus(const std::shared_ptr<kv::Consensus>& c)
    {
      consensus = c;
    }
  };
}
