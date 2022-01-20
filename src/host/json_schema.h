// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <nlohmann/json.hpp>
#include <valijson/adapters/nlohmann_json_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/utils/nlohmann_json_utils.hpp>
#include <valijson/validator.hpp>

namespace json
{
  template <typename T>
  static T validate_json(const nlohmann::json& input, const std::string&)
  {
    // TODO: Implement
  }
}