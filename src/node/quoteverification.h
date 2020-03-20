// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef GET_QUOTE

#  include "codeid.h"
#  include "enclave/oe_shim.h"
#  include "entities.h"
#  include "networktables.h"

#  include <openenclave/bits/report.h>
#  include <openenclave/bits/result.h>
#  include <vector>

namespace ccf
{
  enum QuoteVerificationResult : uint32_t
  {
    VERIFIED = 0,
    FAIL_VERIFY_OE,
    FAIL_VERIFY_CODE_ID_RETIRED,
    FAIL_VERIFY_CODE_ID_NOT_FOUND,
    FAIL_VERIFY_INVALID_QUOTED_CERT,
  };

  inline CodeDigest get_digest_from_parsed_quote(
    const oe_report_t& parsed_quote)
  {
    CodeDigest ret;
    std::copy(
      std::begin(parsed_quote.identity.unique_id),
      std::end(parsed_quote.identity.unique_id),
      ret.begin());
    return ret;
  }

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
      Store::Tx& tx,
      const NetworkTables& network,
      const oe_report_t& parsed_quote)
    {
      auto codeid_view = tx.get_view(network.code_ids);
      CodeStatus code_id_status = CodeStatus::UNKNOWN;

      auto code_digest = get_digest_from_parsed_quote(parsed_quote);
      auto status = codeid_view->get(code_digest);
      if (status)
      {
        code_id_status = *status;
      }

      if (code_id_status != CodeStatus::ACCEPTED)
      {
        return code_id_status == CodeStatus::RETIRED ?
          QuoteVerificationResult::FAIL_VERIFY_CODE_ID_RETIRED :
          QuoteVerificationResult::FAIL_VERIFY_CODE_ID_NOT_FOUND;
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
    static QuoteVerificationResult verify_joiner_node_quote(
      Store::Tx& tx,
      const NetworkTables& network,
      const std::vector<uint8_t>& raw_quote,
      const Cert& raw_cert_pem)
    {
      oe_report_t parsed_quote = {0};

      auto rc = verify_oe_quote(raw_quote, parsed_quote);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      rc = verify_enclave_measurement_against_store(tx, network, parsed_quote);
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

    static QuoteVerificationResult verify_quote(
      const std::vector<uint8_t>& raw_quote,
      const Cert& raw_cert_pem,
      std::set<CodeDigest> allowed_code_ids)
    {
      oe_report_t parsed_quote = {0};

      auto rc = verify_oe_quote(raw_quote, parsed_quote);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      auto code_digest = get_digest_from_parsed_quote(parsed_quote);
      if (allowed_code_ids.find(code_digest) == allowed_code_ids.end())
      {
        return FAIL_VERIFY_CODE_ID_NOT_FOUND;
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

} // namespace ccf
#endif // GET_QUOTE
