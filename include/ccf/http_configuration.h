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
  static const size_t default_max_headers_count = 256;

  struct ParserConfiguration
  {
    std::optional<ds::SizeString> max_body_size = std::nullopt;
    std::optional<ds::SizeString> max_header_size = std::nullopt;
    std::optional<size_t> max_headers_count = std::nullopt;

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

  class RequestPayloadTooLarge : public std::runtime_error
  {
  private:
    // using runtime_error::runtime_error;
    int32_t stream_id;

  public:
    RequestPayloadTooLarge(const std::string& msg, int32_t stream_id_ = 0) :
      std::runtime_error(msg),
      stream_id(stream_id_)
    {}

    int32_t get_stream_id() const
    {
      return stream_id;
    }
  };

  class RequestHeaderTooLarge : public std::runtime_error
  {
    using runtime_error::runtime_error;
  };
}