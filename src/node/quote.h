// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef GET_QUOTE

#  include "code_id.h"
#  include "enclave/oe_shim.h"
#  include "entities.h"
#  include "network_tables.h"

#  include <openenclave/attestation/attester.h>
#  include <openenclave/attestation/sgx/evidence.h>
#  include <openenclave/attestation/verifier.h>
#  include <optional>
#  include <vector>

namespace ccf
{
  // TODO: Re-word!
  enum QuoteVerificationResult : uint32_t
  {
    VERIFIED = 0,
    FAIL_VERIFY_OE,
    FAIL_VERIFY_CODE_ID_RETIRED,
    FAIL_VERIFY_CODE_ID_NOT_FOUND,
    FAIL_VERIFY_INVALID_QUOTED_CERT,
  };

  // TODO: destroy verifier/initializer in destructor!
  class EnclaveEvidenceGenerator
  {
  private:
    static constexpr oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

  public:
    static std::optional<CodeDigest> get_code_id(
      const std::vector<uint8_t>& raw_quote)
    {
      CodeDigest unique_id = {};
      auto rc = verify_oe_quote(raw_quote, unique_id);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        // TODO: Return error
        throw std::logic_error(
          fmt::format("Failed to verify evidence: {}", rc));
      }

      return unique_id;
    }

    static std::optional<std::vector<uint8_t>> get_quote(
      const tls::Pem& node_public_key)
    {
      std::vector<uint8_t> raw_quote;
      crypto::Sha256Hash h{node_public_key.contents()};

      auto rc = oe_attester_initialize();
      if (rc != OE_OK)
      {
        LOG_FAIL_FMT(
          "Failed to initialise evidence attester: {}", oe_result_str(rc));
        return std::nullopt;
      }

      uint8_t* evidence = NULL;
      size_t evidence_size = 0;
      uint8_t* endorsements = NULL;
      size_t endorsements_size = 0;

      LOG_FAIL_FMT("Get quote");

      // TODO: Add custom claims!!

      rc = oe_get_evidence(
        &sgx_remote_uuid,
        0,
        nullptr,
        0,
        nullptr,
        0,
        &evidence,
        &evidence_size,
        &endorsements,
        &endorsements_size);
      if (rc != OE_OK)
      {
        // TODO: Do we actually need to free this???
        oe_free_evidence(evidence);
        oe_free_endorsements(endorsements);
        return std::nullopt;
      }

      raw_quote.assign(evidence, evidence + evidence_size);

      oe_free_report(evidence);
      oe_free_endorsements(endorsements);

      return raw_quote;
    }

  private:
    static QuoteVerificationResult verify_oe_quote(
      const std::vector<uint8_t>& raw_quote, CodeDigest& unique_id)
    {
      // TODO: Create wrapper for this!
      oe_claim_t* claims = nullptr;
      size_t claims_length = 0;

      auto rc = oe_verifier_initialize();
      if (rc != OE_OK)
      {
        LOG_FAIL_FMT(
          "Failed to initialise evidence verifier: {}", oe_result_str(rc));
        // return std::nullopt;
        return QuoteVerificationResult::FAIL_VERIFY_OE;
      }

      rc = oe_verify_evidence(
        &sgx_remote_uuid,
        raw_quote.data(),
        raw_quote.size(),
        nullptr,
        0,
        nullptr,
        0,
        &claims,
        &claims_length);
      if (rc != OE_OK)
      {
        oe_free_claims(claims, claims_length);
        LOG_FAIL_FMT("Failed to verify evidence: {}", oe_result_str(rc));
        // return std::nullopt;
        return QuoteVerificationResult::FAIL_VERIFY_OE;
      }

      for (size_t i = 0; i < claims_length; i++)
      {
        auto claim_name = std::string(claims[i].name);
        if (claim_name == OE_CLAIM_UNIQUE_ID)
        {
          std::copy(
            claims[i].value,
            claims[i].value + claims[i].value_size,
            unique_id.begin());
          break;
        }
      }

      oe_free_claims(claims, claims_length);

      return QuoteVerificationResult::VERIFIED;
    }

    static QuoteVerificationResult verify_enclave_measurement_against_store(
      kv::Tx& tx, const CodeDigest& unique_id)
    {
      auto code_ids = tx.ro<CodeIDs>(Tables::NODE_CODE_IDS);
      auto code_id_status = code_ids->get(unique_id);
      if (!code_id_status.has_value())
      {
        return QuoteVerificationResult::FAIL_VERIFY_CODE_ID_NOT_FOUND;
      }

      if (code_id_status.value() != CodeStatus::ALLOWED_TO_JOIN)
      {
        return QuoteVerificationResult::FAIL_VERIFY_CODE_ID_RETIRED;
      }

      return QuoteVerificationResult::VERIFIED;
    }

    static QuoteVerificationResult verify_quoted_certificate(
      const tls::Pem& cert, const oe_report_t& parsed_quote)
    {
      crypto::Sha256Hash hash{cert.contents()};

      if (
        parsed_quote.report_data_size != OE_REPORT_DATA_SIZE ||
        memcmp(
          hash.h.data(), parsed_quote.report_data, crypto::Sha256Hash::SIZE) !=
          0)
      {
        return QuoteVerificationResult::FAIL_VERIFY_INVALID_QUOTED_CERT;
      }

      return QuoteVerificationResult::VERIFIED;
    }

  public:
    static QuoteVerificationResult verify_quote_against_store(
      kv::Tx& tx, const std::vector<uint8_t>& raw_quote, const tls::Pem& cert)
    {
      (void)cert;
      CodeDigest unique_id;
      // TODO: Also retrieve report data from claims!

      auto rc = verify_oe_quote(raw_quote, unique_id);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      rc = verify_enclave_measurement_against_store(tx, unique_id);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      // TODO: Verify
      // rc = verify_quoted_certificate(cert, parsed_quote);
      // if (rc != QuoteVerificationResult::VERIFIED)
      // {
      //   return rc;
      // }

      return QuoteVerificationResult::VERIFIED;
    }

    static std::pair<http_status, std::string> quote_verification_error(
      QuoteVerificationResult result)
    {
      switch (result)
      {
        case FAIL_VERIFY_OE:
          return std::make_pair(
            HTTP_STATUS_INTERNAL_SERVER_ERROR, "Quote could not be verified");
        case FAIL_VERIFY_CODE_ID_RETIRED:
          return std::make_pair(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            "CODE_ID_RETIRED: Quote does not contain valid enclave "
            "measurement");
        case FAIL_VERIFY_CODE_ID_NOT_FOUND:
          return std::make_pair(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            "CODE_ID_NOT_FOUND: Quote does not contain known enclave "
            "measurement");
        case FAIL_VERIFY_INVALID_QUOTED_CERT:
          return std::make_pair(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            "Quote report data does not contain correct certificate hash");
        default:
          return std::make_pair(
            HTTP_STATUS_INTERNAL_SERVER_ERROR, "Unknown error");
      }
    }
  };
}
#endif
