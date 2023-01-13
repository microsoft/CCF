// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/unit_strings.h"

#include <optional>

namespace http
{
  static const ds::SizeString default_max_body_size = {"1MB"};
  static const ds::SizeString default_max_header_size = {"16KB"};
  static const uint32_t default_max_headers_count = 256;

  // HTTP/2 only, as per nghttp2 defaults
  static const size_t default_max_concurrent_streams_count = 100;
  static const ds::SizeString default_initial_window_size = {"64KB"};
  static const ds::SizeString default_max_frame_size = {"16KB"};

  struct ParserConfiguration
  {
    std::optional<ds::SizeString> max_body_size = std::nullopt;
    std::optional<ds::SizeString> max_header_size = std::nullopt;
    std::optional<uint32_t> max_headers_count = std::nullopt;

    // HTTP/2 only
    std::optional<size_t> max_concurrent_streams_count = std::nullopt;
    std::optional<ds::SizeString> initial_window_size = std::nullopt;
    // Must be between 16KB and 16MB
    // https://www.rfc-editor.org/rfc/rfc7540#section-4.2
    std::optional<ds::SizeString> max_frame_size = std::nullopt;

    bool operator==(const ParserConfiguration& other) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ParserConfiguration);
  DECLARE_JSON_REQUIRED_FIELDS(ParserConfiguration);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ParserConfiguration,
    max_body_size,
    max_header_size,
    max_headers_count,
    max_concurrent_streams_count,
    initial_window_size,
    max_frame_size);
}