// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/code_digest.h"
#include "ccf/service/map.h"

namespace ccf
{
  struct CodeInfo {
    CodeStatus status;
    QuoteFormat origin;
  };
  using CodeIDs = ServiceMap<CodeDigest, CodeInfo>;
  namespace Tables
  {
    static constexpr auto NODE_CODE_IDS = "public:ccf.gov.nodes.code_ids";
  }
}

namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<ccf::CodeDigest>
  {
    static SerialisedEntry to_serialised(const ccf::CodeDigest& code_digest)
    {
      auto hex_str = ds::to_hex(code_digest.data);
      return SerialisedEntry(hex_str.begin(), hex_str.end());
    }

    static ccf::CodeDigest from_serialised(const SerialisedEntry& data)
    {
      ccf::CodeDigest ret;
      ds::from_hex(std::string(data.data(), data.end()), ret.data);
      return ret;
    }
  };

  template <>
  struct JsonSerialiser<ccf::CodeInfo>
  {
    static SerialisedEntry to_serialised(const ccf::CodeInfo& code_info)
    {
      nlohmann::json json_object = nlohmann::json::object();

      json_object["status"] = code_info.status;
      json_object["origin"] = code_info.origin;

      const auto serialised = json_object.dump();

      return SerialisedEntry(serialised.begin(), serialised.end());
    }

    static ccf::CodeInfo from_serialised(const SerialisedEntry& serialised_info)
    {
      ccf::CodeInfo code_info;

      const auto json_object = nlohmann::json::parse(
        serialised_info.begin(),
        serialised_info.end()
      );

      code_info.status = json_object["status"];
      code_info.origin = json_object["origin"];

      return code_info;
    }
  };
}