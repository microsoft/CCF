// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/code_digest.h"
#include "ccf/service/map.h"

namespace ccf
{
  using SnpMeasurements = ServiceMap<CodeDigest, CodeStatus>;

  namespace Tables
  {
    // Note: Only used for SNP
    static constexpr auto NODE_SNP_MEASUREMENTS =
      "public:ccf.gov.nodes.snp.measurements";
  }
}