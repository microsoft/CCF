// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once
#include "ccf/ds/json.h"

#include <vector>

namespace ccf
{
  enum class QuoteFormat
  {
    oe_sgx_v1 = 0,
    insecure_virtual = 1,
    amd_sev_snp_v1 = 2
  };

  DECLARE_JSON_ENUM(
    QuoteFormat,
    {{QuoteFormat::oe_sgx_v1, "OE_SGX_v1"},
     {QuoteFormat::insecure_virtual, "Insecure_Virtual"},
     {QuoteFormat::amd_sev_snp_v1, "AMD_SEV_SNP_v1"}});

  /// Describes a quote (attestation) from trusted hardware
  struct QuoteInfo
  {
    /// Quote format
    QuoteFormat format = QuoteFormat::oe_sgx_v1;
    /// Enclave quote
    std::vector<uint8_t> quote;
    /// Quote endorsements
    std::vector<uint8_t> endorsements;
  };

  DECLARE_JSON_TYPE(QuoteInfo);
  DECLARE_JSON_REQUIRED_FIELDS(QuoteInfo, format, quote, endorsements);
}
