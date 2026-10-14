// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_key.h"
#include "ccf/crypto/cose_verifier.h"

#include <chrono>
#include <span>

namespace ccf::crypto
{
  /// The public key of a DER certificate, as COSE verifiers import it.
  /// @throws std::invalid_argument if the certificate cannot be parsed, or its
  /// key is not supported
  COSEKey cose_key_from_der_cert(std::span<const uint8_t> der);

  /// Whether a COSE signature algorithm verifies with key: the key types
  /// match and, for EC2 keys, so do the curves.
  /// @throws std::runtime_error if alg is not supported
  bool cose_algorithm_matches_key(int64_t alg, const COSEKey& key);

  class COSEVerifier_OpenSSL : public COSEVerifier
  {
  protected:
    COSEKey verify_key;

    explicit COSEVerifier_OpenSSL(COSEKey key) : verify_key(std::move(key)) {}

  public:
    ~COSEVerifier_OpenSSL() override;
    bool verify(
      const std::span<const uint8_t>& envelope,
      std::span<uint8_t>& authned_content) const override;
    [[nodiscard]] bool verify_detached(
      std::span<const uint8_t> envelope,
      std::span<const uint8_t> payload) const override;
    [[nodiscard]] bool verify_decomposed(
      std::span<const uint8_t> phdr,
      std::span<const uint8_t> payload,
      std::span<const uint8_t> sig,
      int64_t alg) const override;
  };

  class COSECertVerifier_OpenSSL : public COSEVerifier_OpenSSL
  {
    using COSEVerifier_OpenSSL::COSEVerifier_OpenSSL;

  public:
    /// Accepts PEM or DER certificate (auto-detects format).
    static std::unique_ptr<COSECertVerifier_OpenSSL> from_any(
      const std::vector<uint8_t>& certificate);
    /// PEM certificate only.
    static std::unique_ptr<COSECertVerifier_OpenSSL> from_pem(const Pem& pem);
    /// DER certificate only.
    static std::unique_ptr<COSECertVerifier_OpenSSL> from_der(
      const std::vector<uint8_t>& der);
  };

  class COSEKeyVerifier_OpenSSL : public COSEVerifier_OpenSSL
  {
  public:
    COSEKeyVerifier_OpenSSL(const Pem& public_key);
    COSEKeyVerifier_OpenSSL(std::span<const uint8_t> public_key_der);
    explicit COSEKeyVerifier_OpenSSL(const COSEKey& key);
  };
}
