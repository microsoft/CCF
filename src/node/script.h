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

    MSGPACK_DEFINE(bytecode, text);
  };

  inline void from_json(const nlohmann::json& j, Script& s)
  {
    const auto bytecode = j.find("bytecode");
    if (bytecode != j.end())
      s.bytecode = std::make_optional<std::vector<uint8_t>>(*bytecode);
    else
      s.text = std::make_optional<std::string>(j["text"]);
  }

  inline void to_json(nlohmann::json& j, const Script& s)
  {
    if (s.bytecode)
      j["bytecode"] = *s.bytecode;
    else if (s.text)
      j["text"] = *s.text;
  }
}
