// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/verifier.h"

#include <chrono>

namespace ccf::crypto
{
  class COSEVerifier
  {
  public:
    virtual bool verify(
      const std::span<const uint8_t>& buf,
      std::span<uint8_t>& authned_content) const = 0;
    [[nodiscard]] virtual bool verify_detached(
      std::span<const uint8_t> buf, std::span<const uint8_t> payload) const = 0;
    virtual ~COSEVerifier() = default;
  };

  using COSEVerifierUniquePtr = std::unique_ptr<COSEVerifier>;

  COSEVerifierUniquePtr make_cose_verifier_from_cert(
    const std::vector<uint8_t>& cert);
  COSEVerifierUniquePtr make_cose_verifier_from_key(const Pem& public_key);

  struct COSEEndorsementValidity
  {
    std::string from_txid;
    std::string to_txid;
  };
  COSEEndorsementValidity extract_cose_endorsement_validity(
    std::span<const uint8_t> cose_msg);
}
