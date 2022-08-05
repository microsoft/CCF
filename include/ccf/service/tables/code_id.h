// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/code_digest.h"
#include "ccf/service/map.h"

namespace ccf
{
  struct CodeInfo {
    CodeStatus status;
    QuoteFormat platform;
  };
  using CodeIDs = ServiceMap<CodeDigest, CodeInfo>;
  namespace Tables
  {
    static constexpr auto NODE_CODE_IDS = "public:ccf.gov.nodes.code_ids";
  }

  inline void to_json(nlohmann::json& j, const CodeInfo& code_info)
  {
      j["status"] = code_info.status;
      j["platform"] = code_info.platform;
  }

  inline void from_json(const nlohmann::json& j, CodeInfo& code_info) {
    // For CCF versions < 3.x, code_id table entries only contained the status.
    // Since we only support SGX nodes in those version, we can assume it's that.
    if (j.is_string()) {
      code_info.status = j;
      code_info.platform = QuoteFormat::oe_sgx_v1;
    }
    else {
      code_info.status = j["status"];
      code_info.platform = j["platform"];
    }
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
}