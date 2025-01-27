// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/measurement.h"
#include "ccf/service/code_status.h"
#include "ccf/service/map.h"

namespace ccf
{
  using VirtualMeasurements =
    ServiceMap<pal::VirtualAttestationMeasurement, CodeStatus>;

  namespace Tables
  {
    static constexpr auto NODE_VIRTUAL_MEASUREMENTS =
      "public:ccf.gov.nodes.virtual.measurements";
  }
}