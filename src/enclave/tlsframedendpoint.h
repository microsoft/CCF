// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tlsendpoint.h"

namespace enclave
{
  class FramedTLSEndpoint : public TLSEndpoint
  {
  protected:
    uint32_t msg_size;
    size_t count;

  public:
    FramedTLSEndpoint(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      msg_size(-1),
      count(0)
    {}

    void recv(const uint8_t* data, size_t size)
    {
      recv_buffered(data, size);

      while (true)
      {
        // Read framed data.
        if (msg_size == (uint32_t)-1)
        {
          auto len = read(4, true);
          if (len.size() == 0)
            return;

          const uint8_t* data = len.data();
          size_t size = len.size();
          msg_size = serialized::read<uint32_t>(data, size);
        }

        // Arbitrary limit on RPC size to stop a client from requesting
        // a very large allocation.
        if (msg_size > 1 << 21)
        {
          close();
          return;
        }

        auto req = read(msg_size, true);
        if (req.size() == 0)
          return;

        msg_size = -1;

        try
        {
          if (!handle_data(req))
            close();
        }
        catch (...)
        {
          // On any exception, close the connection.
          close();
        }
      }
    }

    void send(const std::vector<uint8_t>& data)
    {
      // Write framed data.
      if (data.size() == 0)
        return;

      std::vector<uint8_t> len(4);
      uint8_t* p = len.data();
      size_t size = len.size();
      serialized::write(p, size, (uint32_t)data.size());

      send_buffered(len);
      send_buffered(data);
      flush();
    }
  };
}
