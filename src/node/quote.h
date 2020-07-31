// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef GET_QUOTE

#  include "code_id.h"
#  include "enclave/oe_shim.h"
#  include "entities.h"
#  include "network_tables.h"

#  include <openenclave/attestation/attester.h>
// #  include <openenclave/attestation/evidence.h>
// #  include <openenclave/bits/report.h>
// #  include <openenclave/bits/result.h>
#  include <optional>
#  include <vector>

namespace ccf
{
  inline CodeDigest get_digest_from_parsed_quote(
    const oe_report_t& parsed_quote)
  {
    CodeDigest ret;
    std::copy(
      std::begin(parsed_quote.identity.unique_id),
      std::end(parsed_quote.identity.unique_id),
      ret.begin());

    auto raw_digest = std::vector<uint8_t>(ret.begin(), ret.end());
    return ret;
  }

  class QuoteGenerator
  {
  private:
    // For now, this is re-defined here as Open Enclave 0.10.0 does not expose
    // this value. From Open Enclave > 0.10.0, this can go.
    /**
     * The SGX plugin UUID.
     */
#  define OE_FORMAT_UUID_SGX_ECDSA_P256 \
    { \
      0xa3, 0xa2, 0x1e, 0x87, 0x1b, 0x4d, 0x40, 0x14, 0xb7, 0x0a, 0xa1, 0x25, \
        0xd2, 0xfb, 0xcd, 0x8c \
    }

    static constexpr oe_uuid_t ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};
    // static const oe_uuid_t ecdsa_quote_uuid = {
    //   OE_FORMAT_UUID_SGX_ECDSA_P256_QUOTE};

  public:
    static std::optional<CodeDigest> get_code_id(
      const std::vector<uint8_t>& raw_quote)
    {
      oe_report_t parsed_quote;

      auto rc =
        oe_parse_report(raw_quote.data(), raw_quote.size(), &parsed_quote);
      if (rc != OE_OK)
      {
        LOG_FAIL_FMT("Failed to parse quote: {}", oe_result_str(rc));
        return std::nullopt;
      }

      return get_digest_from_parsed_quote(parsed_quote);
    }

    static std::optional<std::vector<uint8_t>> get_quote(const tls::Pem& cert)
    {
      std::vector<uint8_t> raw_quote;
      crypto::Sha256Hash h{cert.raw()};

      auto rc = oe_attester_initialize();
      if (rc != OE_OK)
      {
        LOG_FAIL_FMT(
          "Failed to initialise attester format: {}", oe_result_str(rc));
        return std::nullopt;
      }

      uint8_t* evidence = NULL;
      size_t evidence_size = 0;
      uint8_t* endorsements = NULL;
      size_t endorsements_size = 0;

      LOG_FAIL_FMT("Get quote");
      std::cout << "Get quote" << std::endl;

      oe_uuid_t selected_format;
      rc = oe_attester_select_format(&ecdsa_uuid, 1, &selected_format);
      if (rc != OE_OK)
      {
        LOG_FAIL_FMT("Failed to select attester format: {}", oe_result_str(rc));
        return std::nullopt;
      }

      rc = oe_get_evidence(
        &selected_format,
        NULL,
        0,
        NULL,
        0,
        &evidence,
        &evidence_size,
        &endorsements,
        &endorsements_size);
      if (rc != OE_OK)
      {
        LOG_FAIL_FMT("Failed to get evidence: {}", oe_result_str(rc));
        oe_free_evidence(evidence);
        oe_free_endorsements(endorsements);
        return std::nullopt;
      }

      raw_quote.assign(evidence, evidence + evidence_size);
      oe_free_report(evidence);
      oe_free_endorsements(endorsements);

      return raw_quote;
    }
  };

  enum QuoteVerificationResult : uint32_t
  {
    VERIFIED = 0,
    FAIL_VERIFY_OE,
    FAIL_VERIFY_CODE_ID_RETIRED,
    FAIL_VERIFY_CODE_ID_NOT_FOUND,
    FAIL_VERIFY_INVALID_QUOTED_CERT,
  };

  class QuoteVerifier
  {
  private:
    static QuoteVerificationResult verify_oe_quote(
      const std::vector<uint8_t>& quote, oe_report_t& parsed_quote)
    {
      oe_result_t result =
        oe_verify_report(quote.data(), quote.size(), &parsed_quote);

      if (result != OE_OK)
      {
        LOG_FAIL_FMT("Quote verification failed: {}", oe_result_str(result));
        return QuoteVerificationResult::FAIL_VERIFY_OE;
      }
      return QuoteVerificationResult::VERIFIED;
    }

    static QuoteVerificationResult verify_enclave_measurement_against_store(
      kv::Tx& tx, CodeIDs& code_ids_table, const oe_report_t& parsed_quote)
    {
      auto code_digest = get_digest_from_parsed_quote(parsed_quote);

      auto codeid_view = tx.get_view(code_ids_table);
      auto code_id_status = codeid_view->get(code_digest);
      if (!code_id_status.has_value())
      {
        // TODO: Revert
        // return QuoteVerificationResult::FAIL_VERIFY_CODE_ID_NOT_FOUND;
      }

      if (code_id_status.value() != CodeStatus::ACCEPTED)
      {
        // TODO: Revert
        // return QuoteVerificationResult::FAIL_VERIFY_CODE_ID_RETIRED;
      }

      return QuoteVerificationResult::VERIFIED;
    }

    static QuoteVerificationResult verify_quoted_certificate(
      const tls::Pem& cert, const oe_report_t& parsed_quote)
    {
      crypto::Sha256Hash hash{cert.raw()};

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
      kv::Tx& tx,
      CodeIDs& code_ids,
      const std::vector<uint8_t>& raw_quote,
      const tls::Pem& cert)
    {
      oe_report_t parsed_quote;

      auto rc = verify_oe_quote(raw_quote, parsed_quote);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      rc = verify_enclave_measurement_against_store(tx, code_ids, parsed_quote);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      rc = verify_quoted_certificate(cert, parsed_quote);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

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
