// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/snp_ioctl5.h"

namespace ccf::pal::snp
{
  static inline bool is_sev_snp()
  {
    return ioctl5::is_sev_snp();
  }

  static ioctl5::Attestation get_attestation(
    const PlatformAttestationReportData& report_data)
  {
    return ioctl5::Attestation(report_data);
  }
};