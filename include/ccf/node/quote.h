// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/quote_info.h"
#include "ccf/service/code_digest.h"
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
    FailedInvalidQuotedPublicKey,
  };

  class EnclaveAttestationProvider
  {
  public:
    static std::optional<CodeDigest> get_code_id(const QuoteInfo& quote_info);

    static QuoteInfo generate_quote(
      const std::vector<uint8_t>& node_public_key_der);

    static QuoteVerificationResult verify_quote_against_store(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      CodeDigest& code_digest);
  };
}
