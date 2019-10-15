// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "ledgerio.h"

namespace asynchost
{
  class Ledger : public LedgerIO
  {
  private:
    std::unique_ptr<ringbuffer::AbstractWriter> to_enclave;

  public:
    Ledger(
      const std::string& filename,
      ringbuffer::AbstractWriterFactory& writer_factory) :
      LedgerIO(filename),
      to_enclave(writer_factory.create_writer_to_inside())
    {}

    Ledger(const Ledger& that) = delete;

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        consensus::ledger_append,
        [this](const uint8_t* data, size_t size) { write_entry(data, size); });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        consensus::ledger_truncate,
        [this](const uint8_t* data, size_t size) {
          auto idx = serialized::read<consensus::Index>(data, size);
          truncate(idx);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, consensus::ledger_get, [&](const uint8_t* data, size_t size) {
          // The enclave has asked for a ledger entry.
          auto [idx] =
            ringbuffer::read_message<consensus::ledger_get>(data, size);

          auto& entry = read_entry(idx);

          if (entry.size() > 0)
          {
            RINGBUFFER_WRITE_MESSAGE(
              consensus::ledger_entry, to_enclave, entry);
          }
          else
          {
            RINGBUFFER_WRITE_MESSAGE(consensus::ledger_no_entry, to_enclave);
          }
        });
    }
  };
}
