// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>

namespace ccf
{
  enum StartType : std::uint8_t
  {
    Start = 1,
    Join = 2,
    Recover = 3,
  };

  constexpr char const* start_type_to_str(StartType type)
  {
    switch (type)
    {
      case StartType::Start:
        return "Start";
      case StartType::Join:
        return "Join";
      case StartType::Recover:
        return "Recover";
      default:
        return "Unknown StartType";
    }
  }
}
