// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tlsendpoint.h"
#include <http-parser/http_parser.h>

namespace enclave
{
  static int on_request(http_parser * parser, const char * at, size_t length);

  class FramedTLSEndpoint : public TLSEndpoint
  {
  protected:
    uint32_t msg_size;
    size_t count;
    http_parser_settings settings;
    http_parser * parser;

  public:
    FramedTLSEndpoint(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      msg_size(-1),
      count(0)
    {
      settings.on_body = on_request;
      parser = static_cast<http_parser *>(malloc(sizeof(http_parser)));
      http_parser_init(parser, HTTP_REQUEST);
      parser->data = (void *) this;
    }

    void recv(const uint8_t* data, size_t size)
    {
      recv_buffered(data, size);

      auto pr_size = pending_read_size();
      auto len = read(pr_size, false); // do a non-consuming read instead

      const uint8_t * d = len.data();
      size_t s = len.size();
      if (!s)
        return;

      LOG_INFO_FMT("Going to parse {} bytes", s);
      size_t nparsed = http_parser_execute(parser, &settings, (const char *) d, s);
    }

    void handle_body(const char * at, size_t length)
    {
      if (length > 0)
      {
        std::vector<uint8_t> req {at, at + length};
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

  static int on_request(http_parser * parser, const char * at, size_t length)
  {
    LOG_INFO_FMT("Received HTTP request with a body of {} bytes", length);
    FramedTLSEndpoint * ep = reinterpret_cast<FramedTLSEndpoint *>(parser->data);
    ep->handle_body(at, length);
    return 0;
  }

}
