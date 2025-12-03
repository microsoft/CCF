// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <string>

namespace ccf
{
  enum class ActorsType : uint8_t
  {
    members = 0,
    users,
    nodes,
    // not to be used
    unknown
  };

  inline bool is_valid_actor(const std::string& actor)
  {
    return actor == "gov" || actor == "app" || actor == "node";
  }

  constexpr auto get_actor_prefix(ActorsType at)
  {
    switch (at)
    {
      case ActorsType::members:
      {
        return "gov";
      }
      case ActorsType::users:
      {
        return "app";
      }
      case ActorsType::nodes:
      {
        return "node";
      }
      default:
      {
        return "";
      }
    }
  }
}
