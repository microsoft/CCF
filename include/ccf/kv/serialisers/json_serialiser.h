// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/serialisers/serialised_entry.h"

#include <nlohmann/json.hpp>

namespace ccf::kv::serialisers
{
  // Converts values to and from JSON, using nlohmann JSON. To add support for
  // custom types, make them convertible to nlohmann::json. You may do this
  // manually with to_json/from_json functions, or use the DECLARE_JSON...
  // macros from include/ccf/ds/json.h to generate converters for POD structs.
  template <typename T>
  struct JsonSerialiser
  {
    static SerialisedEntry to_serialised(const T& t)
    {
      static_assert(
        std::is_convertible_v<T, nlohmann::json>,
        "Cannot convert this type to JSON - either define to_json or use "
        "DECLARE_JSON... macros");

      const nlohmann::json j = t;
      const auto dumped = j.dump();
      return {dumped.begin(), dumped.end()};
    }

    static T from_serialised(const SerialisedEntry& rep)
    {
      const auto j = nlohmann::json::parse(rep.begin(), rep.end());
      return j.get<T>();
    }
  };
}