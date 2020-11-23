// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/tls_endpoint.h"
#include "http_builder.h"
#include "http_proc.h"

#include <algorithm>
#include <cctype>
#include <llhttp/llhttp.h>
#include <map>
#include <queue>
#include <string>
#include <string_view>

namespace http
{
  static uint8_t hex_char_to_int(char c)
  {
    if (c <= '9')
    {
      return c - '0';
    }
    else if (c <= 'F')
    {
      return c - 'A' + 10;
    }
    else if (c <= 'f')
    {
      return c - 'a' + 10;
    }
    return c;
  }

  static std::string url_decode(const std::string_view& s_)
  {
    std::string s(s_);
    char const* src = s.c_str();
    char const* end = s.c_str() + s.size();
    char* dst = s.data();

    while (src < end)
    {
      char const c = *src++;
      if (c == '%' && (src + 1) < end && isxdigit(src[0]) && isxdigit(src[1]))
      {
        const auto a = hex_char_to_int(*src++);
        const auto b = hex_char_to_int(*src++);
        *dst++ = (a << 4) | b;
      }
      else if (c == '+')
      {
        *dst++ = ' ';
      }
      else
      {
        *dst++ = c;
      }
    }

    s.resize(dst - s.data());
    return s;
  }

  static bool status_success(http_status status)
  {
    return status >= 200 && status < 300;
  }

  struct SimpleRequestProcessor : public http::RequestProcessor
  {
  public:
    struct Request
    {
      llhttp_method method;
      std::string path;
      std::string query;
      http::HeaderMap headers;
      std::vector<uint8_t> body;
    };

    std::queue<Request> received;

    virtual void handle_request(
      llhttp_method method,
      const std::string_view& path,
      const std::string& query,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) override
    {
      received.emplace(
        Request{method, std::string(path), std::string(query), headers, body});
    }
  };

  struct SimpleResponseProcessor : public http::ResponseProcessor
  {
  public:
    struct Response
    {
      http_status status;
      http::HeaderMap headers;
      std::vector<uint8_t> body;
    };

    std::queue<Response> received;

    virtual void handle_response(
      http_status status,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) override
    {
      received.emplace(Response{status, headers, body});
    }
  };

  enum State
  {
    DONE,
    IN_MESSAGE
  };

  static int on_msg_begin(llhttp_t* parser);
  static int on_url(llhttp_t* parser, const char* at, size_t length);
  static int on_header_field(llhttp_t* parser, const char* at, size_t length);
  static int on_header_value(llhttp_t* parser, const char* at, size_t length);
  static int on_headers_complete(llhttp_t* parser);
  static int on_body(llhttp_t* parser, const char* at, size_t length);
  static int on_msg_end(llhttp_t* parser);

  inline auto parse_url(const std::string_view& url)
  {
    LOG_TRACE_FMT("Received url to parse: {}", std::string_view(url));

    const auto path_end = url.find('?');
    const auto query_start =
      path_end == std::string::npos ? url.size() : path_end + 1;

    return std::make_pair(url.substr(0, path_end), url.substr(query_start));
  }

  class Parser
  {
  protected:
    llhttp_t parser;
    llhttp_settings_t settings;
    State state = DONE;

    std::vector<uint8_t> body_buf;
    HeaderMap headers;

    std::pair<std::string, std::string> partial_parsed_header = {};

    void complete_header()
    {
      headers.emplace(partial_parsed_header);
      partial_parsed_header.first.clear();
      partial_parsed_header.second.clear();
    }

    Parser(llhttp_type_t type)
    {
      llhttp_settings_init(&settings);

      settings.on_message_begin = on_msg_begin;
      settings.on_header_field = on_header_field;
      settings.on_header_value = on_header_value;
      settings.on_headers_complete = on_headers_complete;
      settings.on_body = on_body;
      settings.on_message_complete = on_msg_end;

      llhttp_init(&parser, type, &settings);
      parser.data = this;
    }

  public:
    void execute(const uint8_t* data, size_t size)
    {
      auto err_no = llhttp_execute(&parser, (const char*)data, size);

      if (err_no != HPE_OK)
      {
        throw std::runtime_error(fmt::format(
          "HTTP parsing failed: '{}: {}' while parsing fragment '{}'",
          llhttp_errno_name(err_no),
          llhttp_get_error_reason(&parser),
          std::string((char const*)data, size)));
      }
    }

    void append_body(const char* at, size_t length)
    {
      if (state == IN_MESSAGE)
      {
        LOG_TRACE_FMT("Appending chunk [{} bytes]", length);
        std::copy(at, at + length, std::back_inserter(body_buf));
      }
      else
      {
        throw std::runtime_error("Receiving content outside of message");
      }
    }

    virtual void new_message()
    {
      if (state == DONE)
      {
        LOG_TRACE_FMT("Entering new message");
        state = IN_MESSAGE;
        body_buf.clear();
        headers.clear();
      }
      else
      {
        throw std::runtime_error(
          "Entering new message when previous message isn't complete");
      }
    }

    virtual void handle_completed_message() = 0;

    void end_message()
    {
      if (state == IN_MESSAGE)
      {
        LOG_TRACE_FMT("Done with message");
        handle_completed_message();
        state = DONE;
      }
      else
      {
        throw std::runtime_error("Ending message, but not in a message");
      }
    }

    void header_field(const char* at, size_t length)
    {
      if (!partial_parsed_header.second.empty())
      {
        complete_header();
      }

      // HTTP headers are stored lowercase as it is easier to verify HTTP
      // signatures later on
      auto f = std::string(at, length);
      nonstd::to_lower(f);
      partial_parsed_header.first.append(f);
    }

    void header_value(const char* at, size_t length)
    {
      partial_parsed_header.second.append(at, length);
    }

    void headers_complete()
    {
      complete_header();
    }
  };

  static int on_msg_begin(llhttp_t* parser)
  {
    Parser* p = reinterpret_cast<Parser*>(parser->data);
    p->new_message();
    return HPE_OK;
  }

  static int on_header_field(llhttp_t* parser, const char* at, size_t length)
  {
    Parser* p = reinterpret_cast<Parser*>(parser->data);
    p->header_field(at, length);
    return HPE_OK;
  }

  static int on_header_value(llhttp_t* parser, const char* at, size_t length)
  {
    Parser* p = reinterpret_cast<Parser*>(parser->data);
    p->header_value(at, length);
    return HPE_OK;
  }

  static int on_headers_complete(llhttp_t* parser)
  {
    Parser* p = reinterpret_cast<Parser*>(parser->data);
    p->headers_complete();
    return HPE_OK;
  }

  static int on_body(llhttp_t* parser, const char* at, size_t length)
  {
    Parser* p = reinterpret_cast<Parser*>(parser->data);
    p->append_body(at, length);
    return HPE_OK;
  }

  static int on_msg_end(llhttp_t* parser)
  {
    Parser* p = reinterpret_cast<Parser*>(parser->data);
    p->end_message();
    return HPE_OK;
  }

  // Request-specific
  class RequestParser : public Parser
  {
  private:
    RequestProcessor& proc;

    std::string url = "";

  public:
    RequestParser(RequestProcessor& proc_) : Parser(HTTP_REQUEST), proc(proc_)
    {
      settings.on_url = on_url;
    }

    void append_url(const char* at, size_t length)
    {
      url.append(at, length);
    }

    void new_message() override
    {
      Parser::new_message();
      url.clear();
    }

    void handle_completed_message() override
    {
      if (url.empty())
      {
        proc.handle_request(
          llhttp_method(parser.method),
          {},
          {},
          std::move(headers),
          std::move(body_buf));
      }
      else
      {
        const auto [path, query] = parse_url(url);
        std::string decoded_query = url_decode(query);
        proc.handle_request(
          llhttp_method(parser.method),
          path,
          decoded_query,
          std::move(headers),
          std::move(body_buf));
      }
    }
  };

  static int on_url(llhttp_t* parser, const char* at, size_t length)
  {
    RequestParser* p = reinterpret_cast<RequestParser*>(parser->data);
    p->append_url(at, length);
    return HPE_OK;
  }

  // Response-specific
  class ResponseParser : public Parser
  {
  private:
    ResponseProcessor& proc;

  public:
    ResponseParser(ResponseProcessor& proc_) :
      Parser(HTTP_RESPONSE),
      proc(proc_)
    {}

    void handle_completed_message() override
    {
      proc.handle_response(
        http_status(parser.status_code),
        std::move(headers),
        std::move(body_buf));
    }
  };
}
