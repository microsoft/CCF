// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/service/code_digest.h"
#include "ccf/service/map.h"

namespace ccf
{
  using SnpMeasurements =
    ServiceMap<pal::SnpAttestationMeasurement, CodeStatus>;

  namespace Tables
  {
    static constexpr auto NODE_SNP_MEASUREMENTS =
      "public:ccf.gov.nodes.snp.measurements";
  }
}