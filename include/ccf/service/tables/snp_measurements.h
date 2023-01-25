// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/code_digest.h"
#include "ccf/service/map.h"

namespace ccf
{
  using SnpMeasurements = ServiceMap<CodeDigest, CodeStatus>;

  using DidUvmEndorsement = std::string;
  using SnpUvmEndorsementDids = ServiceMap<DidUvmEndorsement, CodeStatus>;

  namespace Tables
  {
    static constexpr auto NODE_SNP_MEASUREMENTS =
      "public:ccf.gov.nodes.snp.measurements";

    static constexpr auto NODE_SNP_MEASUREMENTS_UVM_ENDORSEMENT_DIDS =
      "public:ccf.gov.nodes.snp.measurements.uvm_endorsement_dids";
  }
}