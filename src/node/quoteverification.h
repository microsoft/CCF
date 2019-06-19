// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef GET_QUOTE

#  include "enclave/oe_shim.h"
#  include "entities.h"
#  include "networktables.h"

#  include <vector>

namespace ccf
{
  enum QuoteVerificationResult : uint32_t
  {
    VERIFIED = 0,
    FAIL_VERIFY_OE,
    FAIL_VERIFY_CODE_ID_RETIRED,
    FAIL_VERIFY_CODE_ID_NOT_FOUND,
    FAIL_VERIFY_INVALID_HASH,
  };

  class QuoteVerifier
  {
  private:
    static QuoteVerificationResult verify_enclave_measurement(
      Store::Tx& tx,
      NetworkTables& network,
      Cert& cert,
      oe_report_t& parsed_quote)
    {
      // Verify enclave measurement
      auto codeid_view = tx.get_view(network.code_id);
      CodeStatus code_id_status = CodeStatus::UNKNOWN;

      codeid_view->foreach([&parsed_quote, &code_id_status](
                             const CodeVersion& cv, const CodeInfo& ci) {
        if (
          memcmp(
            ci.digest.data(),
            parsed_quote.identity.unique_id,
            CODE_DIGEST_BYTES) == 0)
        {
          code_id_status = ci.status;
        }
      });

      if (code_id_status != CodeStatus::ACCEPTED)
      {
        return code_id_status == CodeStatus::RETIRED ?
          QuoteVerificationResult::FAIL_VERIFY_CODE_ID_RETIRED :
          QuoteVerificationResult::FAIL_VERIFY_CODE_ID_NOT_FOUND;
      }

      // Verify quote data
      crypto::Sha256Hash hash{cert};
      if (
        parsed_quote.report_data_size != crypto::Sha256Hash::SIZE &&
        memcmp(hash.h, parsed_quote.report_data, crypto::Sha256Hash::SIZE) != 0)
      {
        return QuoteVerificationResult::FAIL_VERIFY_INVALID_HASH;
      }
      return QuoteVerificationResult::VERIFIED;
    }

    static bool verify_quote_oe(
      std::vector<uint8_t> quote, oe_report_t& parsed_quote)
    {
      // Parse quote and verify quote data
      oe_result_t result =
        oe_verify_report(quote.data(), quote.size(), &parsed_quote);

      if (result != OE_OK)
      {
        LOG_FAIL_FMT("Quote could not be verified: {}", oe_result_str(result));
        return false;
      }
      return true;
    }

  public:
    static QuoteVerificationResult verify_quote(
      Store::Tx& tx,
      NetworkTables& network,
      std::vector<uint8_t>& quote,
      Cert& cert)
    {
      // Parse quote and verify quote data
      oe_report_t parsed_quote = {0};

      if (!verify_quote_oe(quote, parsed_quote))
      {
        return QuoteVerificationResult::FAIL_VERIFY_OE;
      }

      return verify_enclave_measurement(tx, network, cert, parsed_quote);
    }

    static std::pair<bool, nlohmann::json> quote_verification_error_to_json(
      QuoteVerificationResult result)
    {
      switch (result)
      {
        case FAIL_VERIFY_OE:
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INTERNAL_ERROR, "Quote could not be verified");
        case FAIL_VERIFY_CODE_ID_RETIRED:
          return jsonrpc::error(
            jsonrpc::ErrorCodes::CODE_ID_RETIRED,
            "Quote does not contain valid enclave measurement");
        case FAIL_VERIFY_CODE_ID_NOT_FOUND:
          return jsonrpc::error(
            jsonrpc::ErrorCodes::CODE_ID_NOT_FOUND,
            "Quote does not contain known enclave measurement");
        case FAIL_VERIFY_INVALID_HASH:
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INTERNAL_ERROR,
            "Quote does not contain joining node certificate hash");
        default:
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INTERNAL_ERROR, "Unknown error");
      }
    }
  };

} // namespace ccf
#endif // GET_QUOTE
