// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http_consts.h"
#include "http_status.h"
#include "tls/base64.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <llhttp/llhttp.h>
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

// Most builder function are unused from enclave
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
  static llhttp_method http_method_from_str(const char* s)
  {
#define XX(num, name, string) \
  if (strcmp(s, #string) == 0) \
  { \
    return llhttp_method(num); \
  }
    HTTP_METHOD_MAP(XX)
#undef XX

    throw std::logic_error(fmt::format("Unknown HTTP method '{}'", s));
  }
#pragma clang diagnostic pop

  class Message
  {
  protected:
    HeaderMap headers;
    const uint8_t* body = nullptr;
    size_t body_size = 0;

    Message() = default;

  public:
    const HeaderMap& get_headers() const
    {
      return headers;
    }

    void set_header(std::string k, const std::string& v)
    {
      // Store all headers lower-cased to simplify case-insensitive lookup
      nonstd::to_lower(k);
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
        return body_size;
      }
    }

    const uint8_t* get_content_data() const
    {
      return body;
    }

    void set_body(const std::vector<uint8_t>* b)
    {
      if (b != nullptr)
      {
        set_body(b->data(), b->size());
      }
      else
      {
        set_body(nullptr, 0);
      }
    }

    void set_body(const uint8_t* b, size_t s)
    {
      body = b;
      body_size = s;

      headers[headers::CONTENT_LENGTH] =
        fmt::format("{}", get_content_length());
    }
  };

  class Request : public Message
  {
  private:
    llhttp_method method;
    std::string path = "/";
    std::map<std::string, std::string> query_params = {};

  public:
    Request(const std::string_view& p = "/", llhttp_method m = HTTP_POST) :
      Message(),
      method(m)
    {
      set_path(p);
    }

    llhttp_method get_method() const
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

    void set_query_params(const nlohmann::json& j)
    {
      for (auto it = j.begin(); it != j.end(); ++it)
      {
        set_query_param(it.key(), it.value().dump());
      }
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
        std::string_view((char const*)body, body_size);

      const auto request_string = fmt::format(
        "{} {} HTTP/1.1\r\n"
        "{}"
        "\r\n"
        "{}",
        llhttp_method_name(method),
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
        std::string_view((char const*)body, body_size);

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

// Most builder function are unused from enclave
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

  // Generic
  static std::vector<uint8_t> build_header(
    llhttp_method method, const std::vector<uint8_t>& body)
  {
    Request r("/", method);
    r.set_body(&body);
    return r.build_request(true);
  }

  static std::vector<uint8_t> build_request(
    llhttp_method method, const std::vector<uint8_t>& body)
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
#pragma clang diagnostic pop
}