// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <array>
#  include <openenclave/attestation/attester.h>
#  include <openenclave/attestation/custom_claims.h>
#  include <openenclave/attestation/sgx/evidence.h>
#  include <openenclave/attestation/verifier.h>

namespace ccf::pal
{
  static constexpr size_t sgx_attestation_report_data_size = 32;
  static constexpr size_t sgx_attestation_measurement_size = 32;

  using attestation_report_data =
    std::array<uint8_t, sgx_attestation_report_data_size>;
  using attestation_measurement =
    std::array<uint8_t, sgx_attestation_measurement_size>;

  namespace sgx
  {
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

    struct CustomClaims
    {
      oe_claim_t* data = nullptr;
      size_t length = 0;

      ~CustomClaims()
      {
        oe_free_custom_claims(data, length);
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

    static constexpr oe_uuid_t oe_quote_format = {OE_FORMAT_UUID_SGX_ECDSA};
    static constexpr auto report_data_claim_name = OE_CLAIM_SGX_REPORT_DATA;
  }
}
#endif