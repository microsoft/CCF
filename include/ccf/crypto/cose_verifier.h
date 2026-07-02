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
      const std::span<const uint8_t>& envelope,
      std::span<uint8_t>& authned_content) const = 0;
    [[nodiscard]] virtual bool verify_detached(
      std::span<const uint8_t> envelope,
      std::span<const uint8_t> payload) const = 0;
    [[nodiscard]] virtual bool verify_decomposed(
      std::span<const uint8_t> phdr,
      std::span<const uint8_t> payload,
      std::span<const uint8_t> sig,
      int64_t alg) const = 0;
    virtual ~COSEVerifier() = default;
  };

  using COSEVerifierUniquePtr = std::unique_ptr<COSEVerifier>;

  /// Create a verifier from a certificate in either PEM or DER format.
  /// Tries PEM first, then DER.
  COSEVerifierUniquePtr make_cose_verifier_any_cert(
    const std::vector<uint8_t>& cert);
  COSEVerifierUniquePtr make_cose_verifier_from_pem_cert(const Pem& pem);
  COSEVerifierUniquePtr make_cose_verifier_from_der_cert(
    const std::vector<uint8_t>& der);
  COSEVerifierUniquePtr make_cose_verifier_from_key(const Pem& public_key);
  COSEVerifierUniquePtr make_cose_verifier_from_key(
    std::span<const uint8_t> public_key);

  struct COSEEndorsementValidity
  {
    std::string from_txid;
    std::string to_txid;
  };
  COSEEndorsementValidity extract_cose_endorsement_validity(
    std::span<const uint8_t> cose_msg);
}
