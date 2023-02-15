// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_deprecated.h"
#include "ccf/ds/quote_info.h"
#include "ccf/service/code_digest.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/tx.h"

#include <optional>
#include <vector>

namespace ccf
{
  enum class QuoteVerificationResult
  {
    Verified = 0,
    Failed,
    FailedCodeIdNotFound,
    FailedHostDataDigestNotFound,
    FailedInvalidHostData,
    FailedInvalidQuotedPublicKey,
    FailedUVMEndorsementsNotFound,
  };

  class AttestationProvider
  {
  public:
    /// In SGX case, extracts the MRENCLAVE from an OE quote. This fails on
    /// quotes with expired collateral, so it is recommended to cache code IDs
    /// once they have been successfully extracted.
    static std::optional<CodeDigest> get_code_id(const QuoteInfo& quote_info);

    static std::optional<HostData> get_host_data(const QuoteInfo& quote_info);

    static QuoteVerificationResult verify_quote_against_store(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      CodeDigest& code_digest);
  };

  using EnclaveAttestationProvider CCF_DEPRECATED("Will be removed in 4.x") =
    AttestationProvider;
}