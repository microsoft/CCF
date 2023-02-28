// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/measurement.h"
#include "ccf/service/code_status.h"
#include "ccf/service/map.h"

namespace ccf
{
  using CodeIDs = ServiceMap<pal::SgxAttestationMeasurement, CodeStatus>;

  namespace Tables
  {
    // Note: Only used for SGX
    static constexpr auto NODE_CODE_IDS = "public:ccf.gov.nodes.code_ids";
  }
}