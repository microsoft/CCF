// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"

#include <limits>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>

namespace ccf
{
  using Node2NodeMsg = uint64_t;

  using Cert = std::vector<uint8_t>;

  enum class ActorsType : uint64_t
  {
    members = 0,
    users,
    nodes,
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
      default:
      {
        return "";
      }
    }
  }
}

namespace enclave
{
  enum FrameFormat : uint8_t
  {
    http = 0
  };
}
