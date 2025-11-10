// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/snp_ioctl6.h"

namespace ccf::pal::snp
{
  static inline bool supports_sev_snp()
  {
    return ioctl6::supports_sev_snp();
  }

  static std::unique_ptr<AttestationInterface> get_attestation(
    const PlatformAttestationReportData& report_data)
  {
    if (ioctl6::supports_sev_snp())
    {
      return std::make_unique<ioctl6::Attestation>(report_data);
    }
    throw std::logic_error("SEV-SNP not supported");
  }

  static std::unique_ptr<ioctl6::DerivedKey> make_derived_key(
    const TcbVersionRaw version = {})
  {
    if (ioctl6::supports_sev_snp())
    {
      return std::make_unique<ioctl6::DerivedKey>(version);
    }
    throw std::logic_error("SEV-SNP Derived key not supported");
  }
};