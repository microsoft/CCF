// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/unit_strings.h"
// #include "http/http2_types.h" // TODO: Move http2_types.h to public headers

#include <optional>

namespace http
{
  static const ds::SizeString default_max_body_size = {"1MB"};
  static const ds::SizeString default_max_header_size = {"16KB"};
  static const uint32_t default_max_headers_count = 256;

  struct ParserConfiguration
  {
    std::optional<ds::SizeString> max_body_size = std::nullopt;
    std::optional<ds::SizeString> max_header_size = std::nullopt;
    std::optional<uint32_t> max_headers_count = std::nullopt;

    bool operator==(const ParserConfiguration& other) const
    {
      return max_body_size == other.max_body_size &&
        max_header_size == other.max_header_size &&
        max_headers_count == other.max_headers_count;
    }
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ParserConfiguration);
  DECLARE_JSON_REQUIRED_FIELDS(ParserConfiguration);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ParserConfiguration, max_body_size, max_header_size, max_headers_count);

  class RequestTooLargeException : public std::runtime_error
  {
  private:
    int32_t stream_id; // TODO: Use http2::StreamId type

  public:
    RequestTooLargeException(const std::string& msg, int32_t stream_id = 0) :
      std::runtime_error(msg),
      stream_id(stream_id)
    {}

    int32_t get_stream_id() const
    {
      return stream_id;
    }
  };

  class RequestPayloadTooLargeException : public RequestTooLargeException
  {
  public:
    RequestPayloadTooLargeException(
      const std::string& msg, int32_t stream_id = 0) :
      RequestTooLargeException(msg, stream_id)
    {}
  };

  class RequestHeaderTooLargeException : public RequestTooLargeException
  {
  public:
    RequestHeaderTooLargeException(
      const std::string& msg, int32_t stream_id = 0) :
      RequestTooLargeException(msg, stream_id)
    {}
  };
}