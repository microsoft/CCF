// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/service/map.h"

namespace ccf
{
  using SnpTcbVersionMap = ServiceMap<pal::snp::CPUID, pal::snp::TcbVersion>;

  namespace Tables
  {
    static constexpr auto SNP_TCB_VERSIONS =
      "public:ccf.gov.nodes.snp_tcb_versions";
  }
}