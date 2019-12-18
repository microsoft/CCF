// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <fmt/format_header_only.h>
#include <http-parser/http_parser.h>
#include <map>
#include <string>
#include <vector>

namespace enclave
{
  namespace http
  {
    using HeaderMap = std::map<std::string, std::string, std::less<>>;

    static HeaderMap default_headers()
    {
      HeaderMap headers;
      headers["content-type"] = "application/json";
      return headers;
    }

    static http_method http_method_from_str(const char* s)
    {
#define XX(num, name, string) \
  if (strcmp(s, #string) == 0) \
  { \
    return http_method(num); \
  }
      HTTP_METHOD_MAP(XX)
#undef XX

      throw std::logic_error(fmt::format("Unknown HTTP method '{}'", s));
    }

    class Message
    {
    private:
      HeaderMap headers;

    protected:
      Message() = default;
      Message(const HeaderMap& headers_) : headers(headers_) {}

      std::string get_header_string()
      {
        std::string header_string;
        for (const auto& it : headers)
        {
          header_string += fmt::format("{}: {}\r\n", it.first, it.second);
        }

        return header_string;
      }

    public:
      HeaderMap get_headers() const
      {
        return headers;
      }

      void set_header(const std::string& k, const std::string& v)
      {
        headers[k] = v;
      }

      void clear_headers()
      {
        headers.clear();
      }
    };

    class Request : public Message
    {
    private:
      http_method method;
      std::string path = "/";
      std::map<std::string, std::string> query_params = {};

    public:
      Request(http_method m = HTTP_POST) : method(m), Message(default_headers())
      {}
      Request(const char* s) :
        method(http_method_from_str(s)),
        Message(default_headers())
      {}

      void set_path(const std::string& p)
      {
        if (p.size() > 0 && p[0] == '/')
        {
          path = p;
        }
        else
        {
          path = fmt::format("/{}", p);
        }
      }

      void set_query_param(const std::string& k, const std::string& v)
      {
        query_params[k] = v;
      }

      std::vector<uint8_t> build_request(
        const std::vector<uint8_t>& body, bool header_only = false)
      {
        auto uri = path;
        if (!query_params.empty())
        {
          bool first = true;
          for (const auto& it : query_params)
          {
            uri +=
              fmt::format("{}{}={}", (first ? '?' : '&'), it.first, it.second);
            first = false;
          }
        }

        const auto body_view = header_only ?
          std::string_view() :
          std::string_view((char const*)body.data(), body.size());

        const auto h = fmt::format(
          "{} {} HTTP/1.1\r\n"
          "{}"
          "content-length: {}\r\n"
          "\r\n"
          "{}",
          http_method_str(method),
          uri,
          get_header_string(),
          body.size(),
          body_view);

        return std::vector<uint8_t>(h.begin(), h.end());
      }
    };

    class Response : public Message
    {
    private:
      http_status status;

    public:
      Response(http_status s = HTTP_STATUS_OK) : status(s) {}

      std::vector<uint8_t> build_response_header(
        size_t content_length = 0,
        const std::string& content_type = "application/json")
      {
        std::string rep = "";
        if (content_length > 0)
        {
          rep = fmt::format(
            "HTTP/1.1 {} {}\r\n"
            "{}"
            "Content-Length: {}\r\n"
            "Content-Type: {}\r\n"
            "\r\n",
            status,
            http_status_str(status),
            get_header_string(),
            content_length,
            content_type);
        }
        else
        {
          rep = fmt::format(
            "HTTP/1.1 {} {}\r\n"
            "{}"
            "\r\n",
            status,
            http_status_str(status),
            get_header_string());
        }

        return std::vector<uint8_t>(rep.begin(), rep.end());
      }
    };

    // Generic
    static std::vector<uint8_t> build_header(
      http_method method, const std::vector<uint8_t>& body)
    {
      return Request(method).build_request(body, true);
    }

    static std::vector<uint8_t> build_request(
      http_method method, const std::vector<uint8_t>& body)
    {
      return Request(method).build_request(body, false);
    }

    // HTTP_DELETE
    static std::vector<uint8_t> build_delete_header(
      const std::vector<uint8_t>& body)
    {
      return build_header(HTTP_DELETE, body);
    }

    static std::vector<uint8_t> build_delete_request(
      const std::vector<uint8_t>& body)
    {
      return build_request(HTTP_DELETE, body);
    }

    // HTTP_GET
    static std::vector<uint8_t> build_get_header(
      const std::vector<uint8_t>& body)
    {
      return build_header(HTTP_GET, body);
    }

    static std::vector<uint8_t> build_get_request(
      const std::vector<uint8_t>& body)
    {
      return build_request(HTTP_GET, body);
    }

    // HTTP_POST
    static std::vector<uint8_t> build_post_header(
      const std::vector<uint8_t>& body)
    {
      return build_header(HTTP_POST, body);
    }

    static std::vector<uint8_t> build_post_request(
      const std::vector<uint8_t>& body)
    {
      return build_request(HTTP_POST, body);
    }

    // HTTP_PUT
    static std::vector<uint8_t> build_put_header(
      const std::vector<uint8_t>& body)
    {
      return build_header(HTTP_PUT, body);
    }

    static std::vector<uint8_t> build_put_request(
      const std::vector<uint8_t>& body)
    {
      return build_request(HTTP_PUT, body);
    }
  }
}