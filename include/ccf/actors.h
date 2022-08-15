// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>

namespace ccf
{
  enum class ActorsType : uint64_t
  {
    members = 0,
    users,
    nodes,
    well_known,
    // not to be used
    unknown
  };

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
      case ActorsType::well_known:
      {
        return ".well-known";
      }
      default:
      {
        return "";
      }
    }
  }
}
