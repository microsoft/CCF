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
}