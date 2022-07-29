// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/node/quote.h"

#ifdef GET_QUOTE
#  include "ccf/ds/attestation_types.h"
#  include "ccf/ds/pal.h"
#  include "ccf/service/tables/code_id.h"

namespace ccf
{
  QuoteVerificationResult verify_enclave_measurement_against_store(
    kv::ReadOnlyTx& tx, const CodeDigest& unique_id)
  {
    auto code_ids = tx.ro<CodeIDs>(Tables::NODE_CODE_IDS);
    auto code_id_status = code_ids->get(unique_id);
    if (!code_id_status.has_value())
    {
      return QuoteVerificationResult::FailedCodeIdNotFound;
    }

    return QuoteVerificationResult::Verified;
  }

  QuoteVerificationResult verify_quoted_node_public_key(
    const std::vector<uint8_t>& expected_node_public_key,
    const crypto::Sha256Hash& quoted_hash)
  {
    if (quoted_hash != crypto::Sha256Hash(expected_node_public_key))
    {
      return QuoteVerificationResult::FailedInvalidQuotedPublicKey;
    }

    return QuoteVerificationResult::Verified;
  }

  std::optional<CodeDigest> EnclaveAttestationProvider::get_code_id(
    const QuoteInfo& quote_info)
  {
    CodeDigest unique_id = {};
    crypto::Sha256Hash h;
    if (!Pal::verify_quote(quote_info, unique_id.data, h.h))
    {
      LOG_FAIL_FMT("Failed to verify quote");
      return std::nullopt;
    }

    return unique_id;
  }

  QuoteVerificationResult EnclaveAttestationProvider::
    verify_quote_against_store(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      CodeDigest& code_digest)
  {
    crypto::Sha256Hash quoted_hash;
    if (!Pal::verify_quote(quote_info, code_digest.data, quoted_hash.h))
    {
      return QuoteVerificationResult::Failed;
    }

    auto rc = verify_enclave_measurement_against_store(tx, code_digest);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    return verify_quoted_node_public_key(
      expected_node_public_key_der, quoted_hash);
  }
}
#endif