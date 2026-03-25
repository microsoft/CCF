// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "cose/cose_rs_ffi.h"

#include <chrono>

namespace ccf::crypto
{
  class COSEVerifier_OpenSSL : public COSEVerifier
  {
  protected:
    CoseKey verify_key;

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
    COSECertVerifier_OpenSSL() = default;

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
  };
}
