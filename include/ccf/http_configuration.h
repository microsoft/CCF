// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/unit_strings.h"

#include <optional>

namespace ccf::http
{
  // Default parser limits, used as a DoS protection against
  // requests that are too large.
  static const ccf::ds::SizeString default_max_body_size = {"1MB"};
  static const ccf::ds::SizeString default_max_header_size = {"16KB"};
  static const ccf::ds::SizeString default_max_request_target_size = {"16KB"};
  static const uint32_t default_max_headers_count = 256;

  struct ParserConfiguration
  {
    std::optional<ccf::ds::SizeString> max_body_size = std::nullopt;
    std::optional<ccf::ds::SizeString> max_header_size = std::nullopt;
    std::optional<uint32_t> max_headers_count = std::nullopt;

    // Includes the query string.
    std::optional<ccf::ds::SizeString> max_request_target_size = std::nullopt;

    bool operator==(const ParserConfiguration& other) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ParserConfiguration);
  DECLARE_JSON_REQUIRED_FIELDS(ParserConfiguration);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ParserConfiguration,
    max_body_size,
    max_header_size,
    max_headers_count,
    max_request_target_size);

  // A permissive configuration, used for internally forwarded requests
  // that have already been through application-defined limits.
  static ParserConfiguration permissive_configuration()
  {
    ParserConfiguration config;
    config.max_body_size = "1GB";
    config.max_header_size = "100MB";
    config.max_request_target_size = "100MB";
    config.max_headers_count = 1024;
    return config;
  }
}