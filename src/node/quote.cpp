// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/node/quote.h"

#ifdef GET_QUOTE
#  include "ccf/service/tables/code_id.h"
#  include "node/attestation_types.h"

namespace ccf
{
  QuoteVerificationResult verify_quote(
    const QuoteInfo& quote_info,
    CodeDigest& unique_id,
    crypto::Sha256Hash& hash_node_public_key)
  {
    Claims claims;

    auto rc = oe_verify_evidence(
      &oe_quote_format,
      quote_info.quote.data(),
      quote_info.quote.size(),
      quote_info.endorsements.data(),
      quote_info.endorsements.size(),
      nullptr,
      0,
      &claims.data,
      &claims.length);
    if (rc != OE_OK)
    {
      LOG_FAIL_FMT("Failed to verify evidence: {}", oe_result_str(rc));
      return QuoteVerificationResult::Failed;
    }

    bool unique_id_found = false;
    bool sgx_report_data_found = false;
    for (size_t i = 0; i < claims.length; i++)
    {
      auto& claim = claims.data[i];
      auto claim_name = std::string(claim.name);
      if (claim_name == OE_CLAIM_UNIQUE_ID)
      {
        std::copy(
          claim.value, claim.value + claim.value_size, unique_id.data.begin());
        unique_id_found = true;
      }
      else if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
      {
        // Find sgx report data in custom claims
        CustomClaims custom_claims;
        rc = oe_deserialize_custom_claims(
          claim.value,
          claim.value_size,
          &custom_claims.data,
          &custom_claims.length);
        if (rc != OE_OK)
        {
          throw std::logic_error(fmt::format(
            "Failed to deserialise custom claims", oe_result_str(rc)));
        }

        for (size_t j = 0; j < custom_claims.length; j++)
        {
          auto& custom_claim = custom_claims.data[j];
          if (std::string(custom_claim.name) == sgx_report_data_claim_name)
          {
            if (custom_claim.value_size != hash_node_public_key.SIZE)
            {
              throw std::logic_error(fmt::format(
                "Expected {} of size {}, had size {}",
                sgx_report_data_claim_name,
                hash_node_public_key.SIZE,
                custom_claim.value_size));
            }

            std::copy(
              custom_claim.value,
              custom_claim.value + custom_claim.value_size,
              hash_node_public_key.h.begin());
            sgx_report_data_found = true;
            break;
          }
        }
      }
    }

    if (!unique_id_found || !sgx_report_data_found)
    {
      return QuoteVerificationResult::Failed;
    }

    return QuoteVerificationResult::Verified;
  }

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
    auto rc = verify_quote(quote_info, unique_id, h);
    if (rc != QuoteVerificationResult::Verified)
    {
      LOG_FAIL_FMT("Failed to verify quote: {}", rc);
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

    auto rc = verify_quote(quote_info, code_digest, quoted_hash);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    rc = verify_enclave_measurement_against_store(tx, code_digest);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    return verify_quoted_node_public_key(
      expected_node_public_key_der, quoted_hash);
  }
}
#endif