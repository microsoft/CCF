// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "rpc/jsonrpc.h"

#include <msgpack-c/msgpack.hpp>
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

    MSGPACK_DEFINE(bytecode, text);
  };

  DECLARE_REQUIRED_JSON_FIELDS(Script)
  DECLARE_OPTIONAL_JSON_FIELDS(Script, bytecode, text)
}
