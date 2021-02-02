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

  struct Claims
  {
    oe_claim_t* data = nullptr;
    size_t length = 0;

    ~Claims()
    {
      oe_free_claims(data, length);
    }
  };

  struct SerialisedClaims
  {
    uint8_t* buffer = nullptr;
    size_t size = 0;

    ~SerialisedClaims()
    {
      oe_free_serialized_custom_claims(buffer);
    }
  };

  struct Evidence
  {
    uint8_t* buffer = NULL;
    size_t size = 0;

    ~Evidence()
    {
      oe_free_evidence(buffer);
    }
  };

  struct Endorsements
  {
    uint8_t* buffer = NULL;
    size_t size = 0;

    ~Endorsements()
    {
      oe_free_endorsements(buffer);
    }
  };

  // TODO: Make this a non-static object!
  class EnclaveQuoteGenerator
  {
  private:
    static constexpr oe_uuid_t oe_quote_format = {OE_FORMAT_UUID_SGX_ECDSA};
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

    static CodeDigest get_code_id(const std::vector<uint8_t>& raw_quote)
    {
      CodeDigest unique_id = {};
      crypto::Sha256Hash h;
      auto rc = verify_quote(raw_quote, unique_id, h);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        throw std::logic_error(fmt::format("Failed to verify quote: {}", rc));
      }

      return unique_id;
    }

    static NodeQuoteInfo generate_quote(const tls::Pem& node_public_key)
    {
      NodeQuoteInfo node_quote_info;
      crypto::Sha256Hash h{node_public_key.contents()};

      // TODO: Check if object is initialized!
      Evidence evidence;
      Endorsements endorsements;
      SerialisedClaims serialised_custom_claims;
      oe_claim_t custom_claim;

      // Serialise hash of node's public key as a custom claim
      const size_t custom_claims_count = 1;
      custom_claim.name = const_cast<char*>(sgx_report_data_claim_name);
      custom_claim.value = h.h.data();
      custom_claim.value_size = h.SIZE;

      auto rc = oe_serialize_custom_claims(
        &custom_claim,
        custom_claims_count,
        &serialised_custom_claims.buffer,
        &serialised_custom_claims.size);
      if (rc != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Could not serialise node's public key as quote custom claim: {}",
          oe_result_str(rc)));
      }

      rc = oe_get_evidence(
        &oe_quote_format,
        0,
        serialised_custom_claims.buffer,
        serialised_custom_claims.size,
        nullptr,
        0,
        &evidence.buffer,
        &evidence.size,
        &endorsements.buffer,
        &endorsements.size);
      if (rc != OE_OK)
      {
        throw std::logic_error(
          fmt::format("Failed to get evidence: {}", oe_result_str(rc)));
      }

      node_quote_info.quote.assign(
        evidence.buffer, evidence.buffer + evidence.size);
      node_quote_info.endorsements.assign(
        endorsements.buffer, endorsements.buffer + endorsements.size);

      return node_quote_info;
    }

  private:
    static QuoteVerificationResult verify_quote(
      const std::vector<uint8_t>& raw_quote,
      CodeDigest& unique_id,
      crypto::Sha256Hash& hash_node_public_key)
    {
      Claims claims;

      // TODO: Verify that object is initialised

      auto rc = oe_verify_evidence(
        &oe_quote_format,
        raw_quote.data(),
        raw_quote.size(),
        nullptr,
        0,
        nullptr,
        0,
        &claims.data,
        &claims.length);
      if (rc != OE_OK)
      {
        LOG_FAIL_FMT("Failed to verify evidence: {}", oe_result_str(rc));
        // return std::nullopt;
        return QuoteVerificationResult::FAIL_VERIFY_OE;
      }

      for (size_t i = 0; i < claims.length; i++)
      {
        auto& claim = claims.data[i];
        auto claim_name = std::string(claim.name);
        if (claim_name == OE_CLAIM_UNIQUE_ID)
        {
          std::copy(
            claim.value, claim.value + claim.value_size, unique_id.begin());
        }
        else if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
        {
          Claims custom_claims;
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

          // TODO: Be more relaxed here, it's OK to have more claims!!
          if (custom_claims.length != 1)
          {
            throw std::logic_error(fmt::format(
              "Expected one custom claim, got {}", custom_claims.length));
          }

          auto& custom_claim = custom_claims.data[0];
          if (std::string(custom_claim.name) != sgx_report_data_claim_name)
          {
            throw std::logic_error(fmt::format(
              "Unique custom claim is not {}", sgx_report_data_claim_name));
          }

          if (custom_claim.value_size != hash_node_public_key.SIZE)
          {
            throw std::logic_error(fmt::format(
              "Expected {} of size {}",
              sgx_report_data_claim_name,
              hash_node_public_key.SIZE));
          }

          std::copy(
            custom_claim.value,
            custom_claim.value + custom_claim.value_size,
            hash_node_public_key.h.begin());
        }
      }

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
      const tls::Pem& expected_node_public_key)
    {
      CodeDigest unique_id;
      crypto::Sha256Hash hash_node_public_key;

      auto rc = verify_quote(raw_quote, unique_id, hash_node_public_key);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      rc = verify_enclave_measurement_against_store(tx, unique_id);
      if (rc != QuoteVerificationResult::VERIFIED)
      {
        return rc;
      }

      rc = verify_quoted_node_public_key(
        expected_node_public_key, hash_node_public_key);
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
