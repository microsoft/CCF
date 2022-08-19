// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation_types.h"

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#else
#  include <openenclave/attestation/attester.h>
#endif

namespace ccf::pal
{
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

  static QuoteInfo generate_quote(attestation_report_data&&)
  {
    QuoteInfo node_quote_info = {};
    node_quote_info.format = QuoteFormat::insecure_virtual;
    return node_quote_info;
  }

  static void verify_quote(
    const QuoteInfo& quote_info,
    attestation_measurement& unique_id,
    attestation_report_data& report_data)
  {
    if (quote_info.format != QuoteFormat::insecure_virtual)
    {
      // Virtual enclave cannot verify true (i.e. sgx) enclave quotes
      throw std::logic_error(
        "Cannot verify real attestation report on virtual build");
    }
    unique_id = {};
    report_data = {};
  }

#else

  static QuoteInfo generate_quote(std::array<uint8_t, 32>&& report_data)
  {
    QuoteInfo node_quote_info = {};
    node_quote_info.format = QuoteFormat::oe_sgx_v1;

    Evidence evidence;
    Endorsements endorsements;
    SerialisedClaims serialised_custom_claims;

    // Serialise hash of node's public key as a custom claim
    const size_t custom_claim_length = 1;
    oe_claim_t custom_claim;
    custom_claim.name = const_cast<char*>(sgx_report_data_claim_name);
    custom_claim.value = report_data.data();
    custom_claim.value_size = report_data.size();

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

  static void verify_quote(
    const QuoteInfo& quote_info,
    attestation_measurement& unique_id,
    attestation_report_data& report_data)
  {
    if (quote_info.format != QuoteFormat::oe_sgx_v1)
    {
      throw std::logic_error(
        fmt::format("Cannot verify non OE SGX report: {}", quote_info.format));
    }

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
      throw std::logic_error(
        fmt::format("Failed to verify evidence: {}", oe_result_str(rc)));
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
          claim.value, claim.value + claim.value_size, unique_id.begin());
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
            if (custom_claim.value_size != report_data.size())
            {
              throw std::logic_error(fmt::format(
                "Expected {} of size {}, had size {}",
                sgx_report_data_claim_name,
                report_data.size(),
                custom_claim.value_size));
            }

            std::copy(
              custom_claim.value,
              custom_claim.value + custom_claim.value_size,
              report_data.begin());
            sgx_report_data_found = true;
            break;
          }
        }
      }
    }

    if (!unique_id_found)
    {
      throw std::logic_error("Could not find measurement");
    }

    if (!sgx_report_data_found)
    {
      throw std::logic_error("Could not find report data");
    }
  }

#endif
}