// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tlsendpoint.h"
#include <http-parser/http_parser.h>

namespace enclave
{
  static int on_request(http_parser * parser, const char * at, size_t length);

  namespace http
  {
    class MsgProcessor
    {
      virtual void msg(std::vector<uint8_t> m) = 0;
    };

    enum State
    {
      DONE,
      IN_MESSAGE
    };

    static int on_msg(http_parser * parser);
    static int on_msg_end(http_parser * parser);
    static int on_req(http_parser * parser, const char * at, size_t length);

    class Parser
    {
      private:
        http_parser parser;
        http_parser_settings settings;
        MsgProcessor& proc;
        State state;

      public:
        Parser(MsgProcessor& caller)
        {
          http_parser_settings_init(&settings);
          settings.on_body = on_req;
          settings.on_message_begin = on_msg;
          settings.on_message_complete = on_msg_end;
          http_parser_init(&parser, HTTP_REQUEST);
          parser.data = this;
        }

        size_t execute(const uint8_t* data, size_t size)
        {
          return http_parser_execute(&parser, &settings, (const char *) data, size);
        }

        void new_message()
        {
          if (p->state == DONE)
            p->state == IN_MESSAGE;
          else
            throw std::runtime_error("Entering new message when previous message isn't complete");
        }

        void end_message()
        {
          if (p->state == IN_MESSAGE)
          {
            proc.msg({});
            p->state = DONE;
          }
          else
            throw std::runtime_error("Ending message, but not in a message");
        }
    };

    static int on_msg(http_parser * parser)
    {
      Parser * p = reinterpret_cast<Parser *>(parser->data);
      p->new_message();
      return 0;
    }

    static int on_msg_end(http_parser * parser)
    {
      Parser * p = reinterpret_cast<Parser *>(parser->data);
      p->end_message();
      return 0;      
    }
  }

  class HTTPServer : public TLSEndpoint, public http::MsgProcessor
  {
  protected:
    uint32_t msg_size;
    size_t count;
    http::Parser p;

  public:
    HTTPServer(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      msg_size(-1),
      count(0),
      p(on_request, this) {}

    void recv(const uint8_t* data, size_t size)
    {
      recv_buffered(data, size);

      auto [buf, len] = peek(size);
      if (len == 0)
        return;
      LOG_TRACE_FMT("Going to parse {} bytes", len);
      size_t nparsed = 0;
      while (len > 0)
      {
        size_t nparsed = p.execute(buf, len); //TODO: error handling
        if (nparsed == 0)
          return;
        consume(nparsed);
        buf += nparsed;
        len -= nparsed;
      }
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
      if (data.size() == 0)
      {
        auto hdr = fmt::format("HTTP/1.1 204 No Content\r\n");
        std::vector<uint8_t> h(hdr.begin(), hdr.end());
        send_buffered(h);
      }
      else
      {
        auto hdr = fmt::format("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", data.size());
        std::vector<uint8_t> h(hdr.begin(), hdr.end());
        send_buffered(h);
        send_buffered(data);
      }
      flush();
    }
  };

  static int on_request(http_parser * parser, const char * at, size_t length)
  {
    LOG_INFO_FMT("Received HTTP request with a body of {} bytes", length);
    HTTPServer * ep = reinterpret_cast<HTTPServer *>(parser->data);
    ep->handle_body(at, length);
    return 0;
  }
}
