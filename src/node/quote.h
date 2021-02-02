// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef GET_QUOTE

#  include "code_id.h"
#  include "enclave/oe_shim.h"
#  include "entities.h"
#  include "network_tables.h"

#  include <openenclave/attestation/attester.h>
#  include <openenclave/attestation/custom_claims.h>
#  include <openenclave/attestation/sgx/evidence.h>
#  include <openenclave/attestation/verifier.h>
#  include <optional>
#  include <vector>

namespace ccf
{
  // TODO: To move to nodes.h
  struct NodeQuoteInfo
  {
    std::vector<uint8_t> quote;
    std::vector<uint8_t> endorsements;
  };

  // TODO: Use oe_result_str(rc) whenever possible

  // TODO: Re-word!
  enum QuoteVerificationResult : uint32_t
  {
    VERIFIED = 0,
    FAIL_VERIFY_OE,
    FAIL_VERIFY_CODE_ID_RETIRED,
    FAIL_VERIFY_CODE_ID_NOT_FOUND,
    FAIL_VERIFY_INVALID_QUOTED_PUBLIC_KEY,
  };

  // TODO: Make this a non-static object!
  class EnclaveQuoteGenerator
  {
  private:
    static constexpr oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
    static constexpr auto sgx_report_data_claim_name = OE_CLAIM_SGX_REPORT_DATA;

  public:
    static void initialise()
    {
      auto rc = oe_attester_initialize();
      if (rc != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Failed to initialise evidence attester: {}", oe_result_str(rc)));
      }

      rc = oe_verifier_initialize();
      if (rc != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Failed to initialise evidence verifier: {}", oe_result_str(rc)));
      }
    }

    static void shutdown()
    {
      auto rc = oe_attester_shutdown();
      if (rc != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Failed to initialise evidence attester: {}", oe_result_str(rc)));
      }

      rc = oe_verifier_shutdown();
      if (rc != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Failed to initialise evidence verifier: {}", oe_result_str(rc)));
      }
    }

    static std::optional<CodeDigest> get_code_id(
      const std::vector<uint8_t>& raw_quote)
    {
      CodeDigest unique_id = {};
      crypto::Sha256Hash h; // TODO: Unusued?
      auto rc = verify_oe_quote(raw_quote, unique_id, h);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        // TODO: Return error
        throw std::logic_error(
          fmt::format("Failed to verify evidence: {}", rc));
      }

      return unique_id;
    }

    static std::optional<NodeQuoteInfo> generate_quote(
      const tls::Pem& node_public_key)
    {
      NodeQuoteInfo node_quote_info;
      crypto::Sha256Hash h{node_public_key.contents()};

      // TODO: Check if object is initialized!

      uint8_t* evidence = NULL;
      size_t evidence_size = 0;
      uint8_t* endorsements = NULL;
      size_t endorsements_size = 0;
      uint8_t* custom_claims_buffer = nullptr;
      size_t custom_claims_buffer_size = 0;
      oe_claim_t custom_claim;

      // Serialise hash of node's public key as a custom claim
      const size_t custom_claims_count = 1;
      custom_claim.name = const_cast<char*>(sgx_report_data_claim_name);
      custom_claim.value = h.h.data();
      custom_claim.value_size = h.SIZE;

      auto rc = oe_serialize_custom_claims(
        &custom_claim,
        custom_claims_count,
        &custom_claims_buffer,
        &custom_claims_buffer_size);
      if (rc != OE_OK)
      {
        LOG_FAIL_FMT(
          "Could not serialise node's public key as quote custom claim: {}",
          oe_result_str(rc));
        return std::nullopt;
      }

      rc = oe_get_evidence(
        &sgx_remote_uuid,
        0,
        custom_claims_buffer,
        custom_claims_buffer_size,
        nullptr,
        0,
        &evidence,
        &evidence_size,
        &endorsements,
        &endorsements_size);
      if (rc != OE_OK)
      {
        // TODO: Use wrapper instead!
        oe_free_evidence(evidence);
        oe_free_endorsements(endorsements);
        oe_free_custom_claims(&custom_claim, custom_claims_count);
        LOG_FAIL_FMT("Failed to get evidence: {}", oe_result_str(rc));
        return std::nullopt;
      }

      node_quote_info.quote.assign(evidence, evidence + evidence_size);
      node_quote_info.endorsements.assign(
        endorsements, endorsements + endorsements_size);

      // TODO: use wrapper intead!
      oe_free_report(evidence);
      oe_free_endorsements(endorsements);
      oe_free_custom_claims(&custom_claim, custom_claims_count);

      return node_quote_info;
    }

  private:
    static QuoteVerificationResult verify_oe_quote(
      const std::vector<uint8_t>& raw_quote,
      CodeDigest& unique_id,
      crypto::Sha256Hash& h)
    {
      // TODO: Create wrapper for this!
      oe_claim_t* claims = nullptr;
      size_t claims_length = 0;

      // TODO: Verify that object is initialised

      // auto rc = oe_verifier_initialize();
      // if (rc != OE_OK)
      // {
      //   LOG_FAIL_FMT(
      //     "Failed to initialise evidence verifier: {}", oe_result_str(rc));
      //   return QuoteVerificationResult::FAIL_VERIFY_OE;
      // }

      auto rc = oe_verify_evidence(
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
        LOG_FAIL_FMT("Claim name: {}", claim_name);
        if (claim_name == OE_CLAIM_UNIQUE_ID)
        {
          std::copy(
            claims[i].value,
            claims[i].value + claims[i].value_size,
            unique_id.begin());
          // break; // TODO: Re-add!
        }
        else if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
        {
          oe_claim_t* custom_claims = nullptr;
          size_t custom_claims_length = 0;

          rc = oe_deserialize_custom_claims(
            claims[i].value,
            claims[i].value_size,
            &custom_claims,
            &custom_claims_length);
          if (rc != OE_OK)
          {
            throw std::logic_error("Failed to deserialise custom claims");
          }

          if (custom_claims_length != 1)
          {
            throw std::logic_error("Expected one custom claim!");
          }

          auto custom_claim_name = std::string(custom_claims[0].name);

          if (custom_claim_name != sgx_report_data_claim_name)
          {
            throw std::logic_error(fmt::format(
              "Custom claim is not {}", sgx_report_data_claim_name));
          }

          if (custom_claims[0].value_size != h.SIZE)
          {
            throw std::logic_error(fmt::format(
              "Expected {} of size {}", sgx_report_data_claim_name, h.SIZE));
          }

          LOG_FAIL_FMT("Custom claim: {}", custom_claims[0].name);

          std::copy(
            custom_claims[0].value,
            custom_claims[0].value + custom_claims[0].value_size,
            h.h.begin());
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

    static QuoteVerificationResult verify_quoted_node_public_key(
      const tls::Pem& node_public_key, const crypto::Sha256Hash& h)
    {
      if (h != crypto::Sha256Hash(node_public_key.contents()))
      {
        return QuoteVerificationResult::FAIL_VERIFY_INVALID_QUOTED_PUBLIC_KEY;
      }

      return QuoteVerificationResult::VERIFIED;
    }

  public:
    static QuoteVerificationResult verify_quote_against_store(
      kv::Tx& tx,
      const std::vector<uint8_t>& raw_quote,
      const tls::Pem& node_public_key)
    {
      (void)node_public_key;
      CodeDigest unique_id;
      crypto::Sha256Hash h;
      // TODO: Also retrieve report data from claims!

      auto rc = verify_oe_quote(raw_quote, unique_id, h);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      rc = verify_enclave_measurement_against_store(tx, unique_id);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      rc = verify_quoted_node_public_key(node_public_key, h);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      return QuoteVerificationResult::VERIFIED;
    }

    // TODO: Rename this
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
        case FAIL_VERIFY_INVALID_QUOTED_PUBLIC_KEY:
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
