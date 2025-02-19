// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/service/map.h"
#include "ccf/pal/snp_tcb_version.h"
#include "ccf/ds/json.h"

namespace ccf
{
  using cpu_model = uint8_t; // This may need changing later...
  struct SNP_TCB_Policy {
    cpu_model cpu_model;
    pal::snp::TcbVersion tcb_version;
  };
  DECLARE_JSON_TYPE(SNP_TCB_Policy);
  DECLARE_JSON_REQUIRED_FIELDS(SNP_TCB_Policy, cpu_model, tcb_version);

  using SNPTCBVersionMap = ServiceSet<SNP_TCB_Policy>;
  namespace Tables
  {
    static constexpr auto TCB_Version = "public:ccf.gov.nodes.snp.tcb_version";
  }
}