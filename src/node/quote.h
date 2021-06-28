// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef GET_QUOTE

#  include "code_id.h"
#  include "enclave/oe_shim.h"
#  include "entities.h"
#  include "http/http_status.h"
#  include "network_tables.h"
#  include "node/rpc/node_interface.h"
#  include "quote_info.h"

#  include <openenclave/attestation/attester.h>
#  include <openenclave/attestation/custom_claims.h>
#  include <openenclave/attestation/sgx/evidence.h>
#  include <openenclave/attestation/verifier.h>
#  include <optional>
#  include <vector>

namespace ccf
{
// Unused in all sample apps, but used by node frontend
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wunused-function"
  static std::pair<http_status, std::string> quote_verification_error(
    QuoteVerificationResult result)
  {
    switch (result)
    {
      case QuoteVerificationResult::Failed:
        return std::make_pair(
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Quote could not be verified");
      case QuoteVerificationResult::FailedCodeIdNotFound:
        return std::make_pair(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          "Quote does not contain known enclave measurement");
      case QuoteVerificationResult::FailedInvalidQuotedPublicKey:
        return std::make_pair(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          "Quote report data does not contain node's public key hash");
      default:
        return std::make_pair(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          "Unknown quote verification error");
    }
  }
#  pragma clang diagnostic pop

  // Set of wrappers for safe memory management
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

  class EnclaveAttestationProvider
  {
  private:
    static constexpr oe_uuid_t oe_quote_format = {OE_FORMAT_UUID_SGX_ECDSA};
    static constexpr auto sgx_report_data_claim_name = OE_CLAIM_SGX_REPORT_DATA;

    static QuoteVerificationResult verify_quote(
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
            claim.value,
            claim.value + claim.value_size,
            unique_id.data.begin());
          unique_id_found = true;
        }
        else if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
        {
          // Find sgx report data in custom claims
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

    static QuoteVerificationResult verify_enclave_measurement_against_store(
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

    static QuoteVerificationResult verify_quoted_node_public_key(
      const std::vector<uint8_t>& expected_node_public_key,
      const crypto::Sha256Hash& quoted_hash)
    {
      if (quoted_hash != crypto::Sha256Hash(expected_node_public_key))
      {
        return QuoteVerificationResult::FailedInvalidQuotedPublicKey;
      }

      return QuoteVerificationResult::Verified;
    }

  public:
    static CodeDigest get_code_id(const QuoteInfo& quote_info)
    {
      CodeDigest unique_id = {};
      crypto::Sha256Hash h;
      auto rc = verify_quote(quote_info, unique_id, h);
      if (rc != QuoteVerificationResult::Verified)
      {
        throw std::logic_error(fmt::format("Failed to verify quote: {}", rc));
      }

      return unique_id;
    }

    static QuoteInfo generate_quote(
      const std::vector<uint8_t>& node_public_key_der)
    {
      QuoteInfo node_quote_info;
      node_quote_info.format = QuoteFormat::oe_sgx_v1;

      crypto::Sha256Hash h{node_public_key_der};

      Evidence evidence;
      Endorsements endorsements;
      SerialisedClaims serialised_custom_claims;

      // Serialise hash of node's public key as a custom claim
      const size_t custom_claim_length = 1;
      oe_claim_t custom_claim;
      custom_claim.name = const_cast<char*>(sgx_report_data_claim_name);
      custom_claim.value = h.h.data();
      custom_claim.value_size = h.SIZE;

      auto rc = oe_serialize_custom_claims(
        &custom_claim,
        custom_claim_length,
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

    static QuoteVerificationResult verify_quote_against_store(
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
  };
}
#endif
