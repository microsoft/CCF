// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http_consts.h"
#include "tls/base64.h"
#include "tls/hash.h"

#include <fmt/format_header_only.h>
#include <http-parser/http_parser.h>
#include <map>
#include <string>
#include <vector>

namespace http
{
  using HeaderMap = std::map<std::string, std::string, std::less<>>;

  static std::string get_header_string(const HeaderMap& headers)
  {
    std::string header_string;
    for (const auto& [k, v] : headers)
    {
      header_string += fmt::format("{}: {}\r\n", k, v);
    }

    return header_string;
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
  protected:
    HeaderMap headers;
    const std::vector<uint8_t>* body = nullptr;

    Message() = default;

  public:
    const HeaderMap& get_headers() const
    {
      return headers;
    }

    void set_header(std::string k, const std::string& v)
    {
      // Store all headers lower-cased to simplify case-insensitive lookup
      std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c) {
        return std::tolower(c);
      });
      headers[k] = v;
    }

    void clear_headers()
    {
      headers.clear();
    }

    size_t get_content_length() const
    {
      if (body == nullptr)
      {
        return 0;
      }
      else
      {
        return body->size();
      }
    }

    const uint8_t* get_content_data() const
    {
      if (body == nullptr)
      {
        return nullptr;
      }
      else
      {
        return body->data();
      }
    }

    void set_body(const std::vector<uint8_t>* b)
    {
      body = b;

      headers[headers::CONTENT_LENGTH] =
        fmt::format("{}", get_content_length());
    }
  };

  class Request : public Message
  {
  private:
    http_method method;
    std::string path = "/";
    std::map<std::string, std::string> query_params = {};

  public:
    Request(const std::string_view& p = "/", http_method m = HTTP_POST) :
      Message(),
      method(m)
    {
      set_path(p);
    }

    http_method get_method() const
    {
      return method;
    }

    void set_path(const std::string_view& p)
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

    std::string get_path() const
    {
      return path;
    }

    void set_query_param(const std::string& k, const std::string& v)
    {
      query_params[k] = v;
    }

    std::string get_formatted_query() const
    {
      std::string formatted_query;
      bool first = true;
      for (const auto& it : query_params)
      {
        formatted_query +=
          fmt::format("{}{}={}", (first ? '?' : '&'), it.first, it.second);
        first = false;
      }
      return formatted_query;
    }

    std::vector<uint8_t> build_request(bool header_only = false) const
    {
      const auto uri = fmt::format("{}{}", path, get_formatted_query());

      const auto body_view = (header_only || body == nullptr) ?
        std::string_view() :
        std::string_view((char const*)body->data(), body->size());

      const auto request_string = fmt::format(
        "{} {} HTTP/1.1\r\n"
        "{}"
        "\r\n"
        "{}",
        http_method_str(method),
        uri,
        get_header_string(headers),
        body_view);

      return std::vector<uint8_t>(request_string.begin(), request_string.end());
    }
  };

  class Response : public Message
  {
  private:
    http_status status;

  public:
    Response(http_status s = HTTP_STATUS_OK) : status(s) {}

    std::vector<uint8_t> build_response(bool header_only = false) const
    {
      const auto body_view = (header_only || body == nullptr) ?
        std::string_view() :
        std::string_view((char const*)body->data(), body->size());

      const auto response_string = fmt::format(
        "HTTP/1.1 {} {}\r\n"
        "{}"
        "\r\n"
        "{}",
        status,
        http_status_str(status),
        get_header_string(headers),
        body_view);

      return std::vector<uint8_t>(
        response_string.begin(), response_string.end());
    }
  };

  // Generic
  static std::vector<uint8_t> build_header(
    http_method method, const std::vector<uint8_t>& body)
  {
    Request r("/", method);
    r.set_body(&body);
    return r.build_request(true);
  }

  static std::vector<uint8_t> build_request(
    http_method method, const std::vector<uint8_t>& body)
  {
    Request r("/", method);
    r.set_body(&body);
    return r.build_request(false);
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
  static std::vector<uint8_t> build_get_header(const std::vector<uint8_t>& body)
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
  static std::vector<uint8_t> build_put_header(const std::vector<uint8_t>& body)
  {
    return build_header(HTTP_PUT, body);
  }

  static std::vector<uint8_t> build_put_request(
    const std::vector<uint8_t>& body)
  {
    return build_request(HTTP_PUT, body);
  }
}