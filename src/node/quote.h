// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef GET_QUOTE

#  include "code_id.h"
#  include "enclave/oe_shim.h"
#  include "entities.h"
#  include "network_tables.h"

#  include <openenclave/bits/report.h>
#  include <openenclave/bits/result.h>
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
  public:
    static std::optional<CodeDigest> get_code_id(
      const std::vector<uint8_t>& raw_quote)
    {
      oe_report_t parsed_quote = {0};

      auto rc =
        oe_parse_report(raw_quote.data(), raw_quote.size(), &parsed_quote);
      if (rc != OE_OK)
      {
        LOG_FAIL_FMT("Failed to parse quote: {}", oe_result_str(rc));
        return {};
      }

      return get_digest_from_parsed_quote(parsed_quote);
    }

    static std::optional<std::vector<uint8_t>> get_quote(
      const Cert& raw_cert_pem)
    {
      std::vector<uint8_t> raw_quote;
      crypto::Sha256Hash h{raw_cert_pem};
      uint8_t* quote;
      size_t quote_len = 0;
      oe_report_t parsed_quote = {0};

      auto rc = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        h.h.data(),
        h.SIZE,
        nullptr,
        0,
        &quote,
        &quote_len);

      if (rc != OE_OK)
      {
        oe_free_report(quote);
        LOG_FAIL_FMT("Failed to get quote: {}", oe_result_str(rc));
        return {};
      }

      raw_quote.assign(quote, quote + quote_len);
      oe_free_report(quote);

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
      Store::Tx& tx, CodeIDs& code_ids_table, const oe_report_t& parsed_quote)
    {
      auto code_digest = get_digest_from_parsed_quote(parsed_quote);

      auto codeid_view = tx.get_view(code_ids_table);
      auto code_id_status = codeid_view->get(code_digest);
      if (!code_id_status.has_value())
      {
        return QuoteVerificationResult::FAIL_VERIFY_CODE_ID_NOT_FOUND;
      }

      if (code_id_status.value() != CodeStatus::ACCEPTED)
      {
        return QuoteVerificationResult::FAIL_VERIFY_CODE_ID_RETIRED;
      }

      return QuoteVerificationResult::VERIFIED;
    }

    static QuoteVerificationResult verify_quoted_certificate(
      const Cert& raw_cert_pem, const oe_report_t& parsed_quote)
    {
      crypto::Sha256Hash hash{raw_cert_pem};

      if (
        parsed_quote.report_data_size != crypto::Sha256Hash::SIZE &&
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
      Store::Tx& tx,
      CodeIDs& code_ids,
      const std::vector<uint8_t>& raw_quote,
      const Cert& raw_cert_pem)
    {
      oe_report_t parsed_quote = {0};

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

      rc = verify_quoted_certificate(raw_cert_pem, parsed_quote);
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
