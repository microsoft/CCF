// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/json.h"
#include "ccf/ds/unit_strings.h"

#include <optional>

namespace http
{
  struct ParserConfiguration
  {
    std::optional<ds::SizeString> max_body_size = std::nullopt;
    std::optional<ds::SizeString> max_header_size = std::nullopt;

    bool operator==(const ParserConfiguration& other) const
    {
      return max_body_size == other.max_body_size &&
        max_header_size == other.max_header_size;
    }
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ParserConfiguration);
  DECLARE_JSON_REQUIRED_FIELDS(ParserConfiguration);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ParserConfiguration, max_body_size, max_header_size);
}