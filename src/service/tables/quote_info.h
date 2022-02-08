// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once
#include "ds/json.h"

#include <vector>

namespace ccf
{
  enum class QuoteFormat
  {
    oe_sgx_v1 = 0
  };

  DECLARE_JSON_ENUM(QuoteFormat, {{QuoteFormat::oe_sgx_v1, "OE_SGX_v1"}})

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