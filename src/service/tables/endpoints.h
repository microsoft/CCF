// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint.h"
#include "ccf/service/map.h"

namespace ccf
{
  using DynamicEndpoints =
    ccf::ServiceMap<endpoints::EndpointKey, endpoints::EndpointProperties>;
}

namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<ccf::endpoints::EndpointKey>
  {
    static SerialisedEntry to_serialised(
      const ccf::endpoints::EndpointKey& endpoint_key)
    {
      auto str =
        fmt::format("{} {}", endpoint_key.verb.c_str(), endpoint_key.uri_path);
      return SerialisedEntry(str.begin(), str.end());
    }

    static ccf::endpoints::EndpointKey from_serialised(
      const SerialisedEntry& data)
    {
      std::string str{data.begin(), data.end()};
      auto i = str.find(' ');
      if (i == std::string::npos)
      {
        throw std::logic_error("invalid encoding of endpoint key");
      }
      auto verb = str.substr(0, i);
      auto uri_path = str.substr(i + 1);
      return {uri_path, verb};
    }
  };
}