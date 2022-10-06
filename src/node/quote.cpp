// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/node/quote.h"

#include "ccf/pal/attestation.h"
#include "ccf/service/tables/code_id.h"

namespace ccf
{
  QuoteVerificationResult verify_enclave_measurement_against_store(
    kv::ReadOnlyTx& tx,
    const CodeDigest& unique_id,
    const QuoteFormat& quote_format)
  {
    auto code_ids = tx.ro<CodeIDs>(Tables::NODE_CODE_IDS);
    auto code_id_info = code_ids->get(unique_id);
    if (!code_id_info.has_value())
    {
      return QuoteVerificationResult::FailedCodeIdNotFound;
    }
    if (code_id_info->platform != quote_format)
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

  std::optional<CodeDigest> AttestationProvider::get_code_id(
    const QuoteInfo& quote_info)
  {
    CodeDigest unique_id = {};
    pal::attestation_report_data r = {};
    try
    {
      pal::verify_quote(quote_info, unique_id.data, r);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return std::nullopt;
    }

    return unique_id;
  }

  QuoteVerificationResult AttestationProvider::verify_quote_against_store(
    kv::ReadOnlyTx& tx,
    const QuoteInfo& quote_info,
    const std::vector<uint8_t>& expected_node_public_key_der,
    CodeDigest& code_digest)
  {
    crypto::Sha256Hash quoted_hash;
    pal::attestation_report_data report;
    try
    {
      pal::verify_quote(quote_info, code_digest.data, report);

      // Attestation report may be different sizes depending on the platform.
      std::copy(
        report.begin(),
        report.begin() + crypto::Sha256Hash::SIZE,
        quoted_hash.h.begin());
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return QuoteVerificationResult::Failed;
    }

    if (quote_info.format == QuoteFormat::insecure_virtual)
    {
      LOG_FAIL_FMT("Skipped attestation report verification");
      return QuoteVerificationResult::Verified;
    }

    auto rc = verify_enclave_measurement_against_store(
      tx, code_digest, quote_info.format);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    return verify_quoted_node_public_key(
      expected_node_public_key_der, quoted_hash);
  }
}