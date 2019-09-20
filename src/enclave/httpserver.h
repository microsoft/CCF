// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tlsendpoint.h"

#include <http-parser/http_parser.h>

namespace enclave
{
  namespace http
  {
    std::vector<uint8_t> post(const std::string& body)
    {
      auto req = fmt::format(
        "POST / HTTP/1.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: {}\r\n\r\n{}",
        body.size(),
        body);
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
      Parser(MsgProcessor& caller) : proc(caller)
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
        auto parsed =
          http_parser_execute(&parser, &settings, (const char*)data, size);
        LOG_TRACE_FMT("Parsed {} bytes", parsed);
        auto err = HTTP_PARSER_ERRNO(&parser);
        if (err)
          throw std::runtime_error(fmt::format(
            "HTTP parsing failed: {}: {}",
            http_errno_name(err),
            http_errno_description(err)));
        // TODO: check for http->upgrade
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
          throw std::runtime_error("Receiving content outside of message");
      }

      void new_message()
      {
        if (state == DONE)
        {
          LOG_TRACE_FMT("Entering new message");
          state = IN_MESSAGE;
        }
        else
          throw std::runtime_error(
            "Entering new message when previous message isn't complete");
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
          throw std::runtime_error("Ending message, but not in a message");
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

  class HTTPServer : public TLSEndpoint, public http::MsgProcessor
  {
  protected:
    http::Parser p;

  public:
    HTTPServer(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      p(*this)
    {}

    void recv(const uint8_t* data, size_t size)
    {
      recv_buffered(data, size);

      auto buf = read(size, false);
      if (buf.size() == 0)
        return;
      LOG_TRACE_FMT("Going to parse {} bytes", buf.size());
      LOG_TRACE_FMT("Going to parse [{}]", std::string(buf.begin(), buf.end()));

      size_t nparsed = p.execute(buf.data(), buf.size());
      if (nparsed == 0)
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
      if (data.size() == 0)
      {
        auto hdr = fmt::format("HTTP/1.1 204 No Content\r\n");
        std::vector<uint8_t> h(hdr.begin(), hdr.end());
        send_buffered(h);
      }
      else
      {
        auto hdr = fmt::format(
          "HTTP/1.1 200 OK\r\nContent-Type: "
          "application/json\r\nContent-Length: {}\r\n\r\n",
          data.size());
        std::vector<uint8_t> h(hdr.begin(), hdr.end());
        send_buffered(h);
        send_buffered(data);
      }
      flush();
    }
  };

  // TODO: NAMING
  class HTTPClient : public TLSEndpoint, public http::MsgProcessor
  {
  protected:
    http::Parser p;

  public:
    HTTPClient(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      p(*this)
    {}

    void recv(const uint8_t* data, size_t size)
    {
      recv_buffered(data, size);

      auto buf = read(size, false);
      if (buf.size() == 0)
        return;
      LOG_TRACE_FMT("Going to parse {} bytes", buf.size());
      LOG_TRACE_FMT("Going to parse [{}]", std::string(buf.begin(), buf.end()));

      size_t nparsed = p.execute(buf.data(), buf.size());
      if (nparsed == 0)
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
      auto req = http::post(std::string(data.begin(), data.end()));
      send_buffered(req);
      flush();
    }
  };
}
