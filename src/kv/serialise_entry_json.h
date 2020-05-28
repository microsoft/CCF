// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <nlohmann/json.hpp>
#include <vector>

namespace kv::serialisers
{
  template <typename T>
  struct JsonSerialiser
  {
    using Bytes = std::vector<uint8_t>;

    static Bytes to_serialised(const T& t)
    {
      const nlohmann::json j = t;
      const auto dumped = j.dump();
      return Bytes(dumped.begin(), dumped.end());
    }

    static T from_serialised(const Bytes& rep)
    {
      const auto j = nlohmann::json::parse(rep);
      return j.get<T>();
    }
  };
}