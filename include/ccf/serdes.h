// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <string>
#include <vector>

namespace serdes
{
  enum class Pack
  {
    Text,
    MsgPack
  };

  inline std::vector<uint8_t> pack(const nlohmann::json& j, Pack pack)
  {
    switch (pack)
    {
      case Pack::Text:
      {
        auto s = j.dump();
        return std::vector<uint8_t>{s.begin(), s.end()};
      }

      case Pack::MsgPack:
        return nlohmann::json::to_msgpack(j);
    }

    throw std::logic_error("Invalid serdes::Pack");
  }

  inline nlohmann::json unpack(const std::vector<uint8_t>& data, Pack pack)
  {
    switch (pack)
    {
      case Pack::Text:
        return nlohmann::json::parse(data);

      case Pack::MsgPack:
        return nlohmann::json::from_msgpack(data);
    }

    throw std::logic_error("Invalid serdes::Pack");
  }

  inline std::optional<serdes::Pack> detect_pack(
    const std::vector<uint8_t>& input)
  {
    if (input.size() == 0)
    {
      return std::nullopt;
    }

    if (input[0] == '{')
    {
      return serdes::Pack::Text;
    }
    else
    {
      return serdes::Pack::MsgPack;
    }
  }
}
