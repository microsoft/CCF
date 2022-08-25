// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/quote_info.h"
#include "ccf/service/code_digest.h"
#include "ccf/service/map.h"

namespace ccf
{
  struct ExecutorCodeInfo
  {
    CodeStatus status;
    QuoteFormat platform;
    // FIXLater: Add more metadata that includes allowed URIS for each executor
  };
  using ExecutorCodeIDs = ServiceMap<CodeDigest, CodeInfo>;
  namespace Tables
  {
    static constexpr auto EXECUTOR_CODE_IDS =
      "public:ccf.gov.nodes.executor_code_ids";
  }

  inline void to_json(nlohmann::json& j, const ExecutorCodeInfo& code_info)
  {
    j["status"] = code_info.status;
    j["platform"] = code_info.platform;
  }

  inline void from_json(const nlohmann::json& j, ExecutorCodeInfo& code_info)
  {
    if (j.is_string())
    {
      code_info.status = j;
      code_info.platform = QuoteFormat::amd_sev_snp_v1;
    }
    else
    {
      code_info.status = j["status"];
      code_info.platform = j["platform"];
    }
  }
}