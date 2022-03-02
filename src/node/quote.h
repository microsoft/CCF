// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// #ifdef GET_QUOTE // TODO: Move GET_QUOTE switches to implementation only

#include "ccf/http_status.h"
#include "ccf/quote_info.h"
#include "ccf/service/tables/code_id.h"
#include "node/rpc/node_interface.h"

#include <optional>
#include <vector>

namespace ccf
{
  class EnclaveAttestationProvider
  {
  private:
    static QuoteVerificationResult verify_quote(
      const QuoteInfo& quote_info,
      CodeDigest& unique_id,
      crypto::Sha256Hash& hash_node_public_key);

    static QuoteVerificationResult verify_enclave_measurement_against_store(
      kv::ReadOnlyTx& tx, const CodeDigest& unique_id);

    static QuoteVerificationResult verify_quoted_node_public_key(
      const std::vector<uint8_t>& expected_node_public_key,
      const crypto::Sha256Hash& quoted_hash);

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
