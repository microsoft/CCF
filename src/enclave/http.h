// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tlsendpoint.h"

#include <http-parser/http_parser.h>

namespace enclave
{
  namespace http
  {
    // TODO: Split into a request formatter class
    std::vector<uint8_t> post_header(const std::vector<uint8_t>& body)
    {
      auto req = fmt::format(
        "POST / HTTP/1.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: {}\r\n\r\n",
        body.size());
      return std::vector<uint8_t>(req.begin(), req.end());
    }

    class MsgProcessor
    {
    public:
      virtual void msg(std::vector<uint8_t> m) = 0;
    };

    enum State
    {
      DONE,
      IN_MESSAGE
    };

    static int on_msg(http_parser* parser);
    static int on_msg_end(http_parser* parser);
    static int on_req(http_parser* parser, const char* at, size_t length);

    class Parser
    {
    private:
      http_parser parser;
      http_parser_settings settings;
      MsgProcessor& proc;
      State state = DONE;
      std::vector<uint8_t> buf;

    public:
      Parser(http_parser_type type, MsgProcessor& proc_) : proc(proc_)
      {
        http_parser_settings_init(&settings);
        settings.on_body = on_req;
        settings.on_message_begin = on_msg;
        settings.on_message_complete = on_msg_end;
        http_parser_init(&parser, type);
        parser.data = this;
      }

      size_t execute(const uint8_t* data, size_t size)
      {
        auto parsed =
          http_parser_execute(&parser, &settings, (const char*)data, size);
        LOG_TRACE_FMT("Parsed {} bytes", parsed);
        auto err = HTTP_PARSER_ERRNO(&parser);
        if (err)
          throw std::runtime_error(fmt::format(
            "HTTP parsing failed: {}: {}",
            http_errno_name(err),
            http_errno_description(err)));
        // TODO: check for http->upgrade to support websockets
        return parsed;
      }

      void append(const char* at, size_t length)
      {
        if (state == IN_MESSAGE)
        {
          LOG_TRACE_FMT("Appending chunk [{}]", std::string(at, at + length));
          std::copy(at, at + length, std::back_inserter(buf));
        }
        else
        {
          throw std::runtime_error("Receiving content outside of message");
        }
      }

      void new_message()
      {
        if (state == DONE)
        {
          LOG_TRACE_FMT("Entering new message");
          state = IN_MESSAGE;
        }
        else
        {
          throw std::runtime_error(
            "Entering new message when previous message isn't complete");
        }
      }

      void end_message()
      {
        if (state == IN_MESSAGE)
        {
          LOG_TRACE_FMT("Done with message");
          proc.msg(std::move(buf));
          state = DONE;
        }
        else
        {
          throw std::runtime_error("Ending message, but not in a message");
        }
      }
    };

    class ResponseHeaderEmitter
    {
    public:
      static std::vector<uint8_t> emit(const std::vector<uint8_t>& data)
      {
        if (data.size() == 0)
        {
          auto hdr = fmt::format("HTTP/1.1 204 No Content\r\n");
          return std::vector<uint8_t>(hdr.begin(), hdr.end());
        }
        else
        {
          auto hdr = fmt::format(
            "HTTP/1.1 200 OK\r\nContent-Type: "
            "application/json\r\nContent-Length: {}\r\n\r\n",
            data.size());
          return std::vector<uint8_t>(hdr.begin(), hdr.end());
        }
      }
    };

    class RequestHeaderEmitter
    {
    public:
      static std::vector<uint8_t> emit(const std::vector<uint8_t>& data)
      {
        return http::post_header(data);
      }
    };

    static int on_msg(http_parser* parser)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->new_message();
      return 0;
    }

    static int on_msg_end(http_parser* parser)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->end_message();
      return 0;
    }

    static int on_req(http_parser* parser, const char* at, size_t length)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->append(at, length);
      return 0;
    }
  }

  template <class E>
  class HTTPEndpoint : public TLSEndpoint, public http::MsgProcessor
  {
  protected:
    http::Parser p;

  public:
    HTTPEndpoint(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx)
    {
      LOG_FAIL_FMT("FAIL");
      assert(false);
    }

    void recv(const uint8_t* data, size_t size)
    {
      recv_buffered(data, size);

      LOG_TRACE_FMT("recv called with {} bytes", size);
      auto buf = read(4096, false); // TODO: retry if more was pending
      LOG_TRACE_FMT("read got {}", buf.size());

      if (buf.size() == 0)
        return;

      LOG_TRACE_FMT(
        "Going to parse {} bytes: [{}]",
        buf.size(),
        std::string(buf.begin(), buf.end()));

      if (p.execute(buf.data(), buf.size()) == 0)
        return;
    }

    virtual void msg(std::vector<uint8_t> m)
    {
      if (m.size() > 0)
      {
        try
        {
          if (!handle_data(m))
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
      send_buffered(E::emit(data));
      if (data.size() > 0)
        send_buffered(data);
      flush();
    }
  };

  template <>
  HTTPEndpoint<http::RequestHeaderEmitter>::HTTPEndpoint(
    size_t session_id,
    ringbuffer::AbstractWriterFactory& writer_factory,
    std::unique_ptr<tls::Context> ctx) :
    TLSEndpoint(session_id, writer_factory, std::move(ctx)),
    p(HTTP_RESPONSE, *this)
  {}

  template <>
  HTTPEndpoint<http::ResponseHeaderEmitter>::HTTPEndpoint(
    size_t session_id,
    ringbuffer::AbstractWriterFactory& writer_factory,
    std::unique_ptr<tls::Context> ctx) :
    TLSEndpoint(session_id, writer_factory, std::move(ctx)),
    p(HTTP_REQUEST, *this)
  {}
}
