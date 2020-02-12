// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "httpbuilder.h"
#include "tlsendpoint.h"

#include <algorithm>
#include <cctype>
#include <http-parser/http_parser.h>
#include <map>
#include <queue>
#include <string>

namespace enclave
{
  namespace http
  {
    class MsgProcessor
    {
    public:
      virtual void handle_message(
        http_method method,
        const std::string_view& path,
        const std::string_view& query,
        const HeaderMap& headers,
        const std::vector<uint8_t>& body) = 0;
    };

    struct SimpleMsgProcessor : public enclave::http::MsgProcessor
    {
    public:
      struct Msg
      {
        http_method method;
        std::string path;
        std::string query;
        enclave::http::HeaderMap headers;
        std::vector<uint8_t> body;
      };

      std::queue<Msg> received;

      virtual void handle_message(
        http_method method,
        const std::string_view& path,
        const std::string_view& query,
        const enclave::http::HeaderMap& headers,
        const std::vector<uint8_t>& body) override
      {
        received.emplace(
          Msg{method, std::string(path), std::string(query), headers, body});
      }
    };

    enum State
    {
      DONE,
      IN_MESSAGE
    };

    static int on_msg_begin(http_parser* parser);
    static int on_url(http_parser* parser, const char* at, size_t length);
    static int on_header_field(
      http_parser* parser, const char* at, size_t length);
    static int on_header_value(
      http_parser* parser, const char* at, size_t length);
    static int on_headers_complete(http_parser* parser);
    static int on_req(http_parser* parser, const char* at, size_t length);
    static int on_msg_end(http_parser* parser);

    inline std::string_view extract_url_field(
      const http_parser_url& parser_url,
      http_parser_url_fields field,
      const std::string& url)
    {
      if ((1 << field) & parser_url.field_set)
      {
        const auto& data = parser_url.field_data[field];
        const auto start = url.data();
        return std::string_view(start + data.off, data.len);
      }

      return {};
    }

    class Parser
    {
    private:
      http_parser parser;
      http_parser_settings settings;
      MsgProcessor& proc;
      State state = DONE;
      std::vector<uint8_t> buf;
      std::string url = "";
      std::string_view path = {};
      std::string_view query = {};
      HeaderMap headers;

      std::pair<std::string, std::string> partial_parsed_header = {};

      void complete_header()
      {
        headers.emplace(partial_parsed_header);
        partial_parsed_header.first.clear();
        partial_parsed_header.second.clear();
      }

    public:
      Parser(http_parser_type type, MsgProcessor& proc_) : proc(proc_)
      {
        http_parser_settings_init(&settings);

        settings.on_message_begin = on_msg_begin;
        settings.on_url = on_url;
        settings.on_header_field = on_header_field;
        settings.on_header_value = on_header_value;
        settings.on_headers_complete = on_headers_complete;
        settings.on_body = on_req;
        settings.on_message_complete = on_msg_end;

        http_parser_init(&parser, type);
        parser.data = this;
      }

      http_parser* get_raw_parser()
      {
        return &parser;
      }

      size_t execute(const uint8_t* data, size_t size)
      {
        auto parsed =
          http_parser_execute(&parser, &settings, (const char*)data, size);

        LOG_TRACE_FMT("Parsed {} bytes", parsed);

        auto err = HTTP_PARSER_ERRNO(&parser);
        if (err)
        {
          throw std::runtime_error(fmt::format(
            "HTTP parsing failed: {}: {}",
            http_errno_name(err),
            http_errno_description(err)));
        }

        return parsed;
      }

      void append(const char* at, size_t length)
      {
        if (state == IN_MESSAGE)
        {
          LOG_TRACE_FMT("Appending chunk [{}]", std::string_view(at, length));
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
          url.clear();
          path = {};
          query = {};
          buf.clear();
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
          proc.handle_message(
            http_method(parser.method), path, query, headers, buf);
          state = DONE;
        }
        else
        {
          throw std::runtime_error("Ending message, but not in a message");
        }
      }

      void append_url(const char* at, size_t length)
      {
        url.append(at, length);
      }

      void parse_url()
      {
        LOG_TRACE_FMT("Received url to parse: {}", std::string_view(url));

        http_parser_url parser_url;
        http_parser_url_init(&parser_url);

        const auto err =
          http_parser_parse_url(url.data(), url.size(), 0, &parser_url);
        if (err != 0)
        {
          throw std::runtime_error(fmt::format("Error parsing url: {}", err));
        }

        path = extract_url_field(parser_url, UF_PATH, url);
        query = extract_url_field(parser_url, UF_QUERY, url);
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
        std::transform(f.begin(), f.end(), f.begin(), [](unsigned char c) {
          return std::tolower(c);
        });
        partial_parsed_header.first.append(f);
      }

      void header_value(const char* at, size_t length)
      {
        partial_parsed_header.second.append(at, length);
      }

      void headers_complete()
      {
        complete_header();
        parse_url();
      }
    };

    static int on_msg_begin(http_parser* parser)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->new_message();
      return 0;
    }

    static int on_url(http_parser* parser, const char* at, size_t length)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->append_url(at, length);
      return 0;
    }

    static int on_header_field(
      http_parser* parser, const char* at, size_t length)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->header_field(at, length);
      return 0;
    }

    static int on_header_value(
      http_parser* parser, const char* at, size_t length)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->header_value(at, length);
      return 0;
    }

    static int on_headers_complete(http_parser* parser)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->headers_complete();
      return 0;
    }

    static int on_req(http_parser* parser, const char* at, size_t length)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->append(at, length);
      return 0;
    }

    static int on_msg_end(http_parser* parser)
    {
      Parser* p = reinterpret_cast<Parser*>(parser->data);
      p->end_message();
      return 0;
    }
  }
}
