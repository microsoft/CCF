// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <optional>
#include <stdint.h>
#include <string>
#include <vector>

namespace ccf
{
  /** A script, e.g., a Lua script
   * The script may be in string or bytecode format.
   */
  struct Script
  {
    std::optional<std::vector<uint8_t>> bytecode;
    std::optional<std::string> text;

    Script() = default;
    Script(std::string script_)
    {
      text = std::move(script_);
    };

    Script(std::vector<uint8_t> script_)
    {
      bytecode = std::move(script_);
    };

    bool operator==(const Script& other) const
    {
      return bytecode == other.bytecode && text == other.text;
    }

    bool operator!=(const Script& other) const
    {
      return !operator==(other);
    }
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Script);

  // Current limitation of the JSON macros: It is necessary to defined
  // DECLARE_JSON_REQUIRED_FIELDS for Script even though there are no required
  // fields. This raises some compiler warnings that are disabled locally.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
  DECLARE_JSON_REQUIRED_FIELDS(Script);
#pragma clang diagnostic pop

  DECLARE_JSON_OPTIONAL_FIELDS(Script, bytecode, text);
}
