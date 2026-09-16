// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include "ccf/crypto/mldsa_public_key.h"
#  include "ccf/crypto/openssl/openssl_wrappers.h"

#  include <optional>

namespace ccf::crypto
{
  class MLDSAPublicKey_OpenSSL : public MLDSAPublicKey
  {
  protected:
    OpenSSL::Unique_PKEY key{nullptr, EVP_PKEY_free, false};

    MLDSAPublicKey_OpenSSL() = default;

  public:
    explicit MLDSAPublicKey_OpenSSL(
      const Pem& pem, std::optional<MLDSAParameterSet> expected = std::nullopt);
    explicit MLDSAPublicKey_OpenSSL(
      std::span<const uint8_t> der,
      std::optional<MLDSAParameterSet> expected = std::nullopt);
    MLDSAPublicKey_OpenSSL(const MLDSAPublicKey_OpenSSL&) = delete;
    MLDSAPublicKey_OpenSSL& operator=(const MLDSAPublicKey_OpenSSL&) = delete;
    ~MLDSAPublicKey_OpenSSL() override = default;

    [[nodiscard]] MLDSAParameterSet get_parameter_set() const override;

    [[nodiscard]] Pem public_key_pem() const override;
    [[nodiscard]] std::vector<uint8_t> public_key_der() const override;

    bool verify(
      std::span<const uint8_t> contents,
      std::span<const uint8_t> signature,
      std::span<const uint8_t> context = {}) override;
  };
}
#endif // OPENSSL_VERSION_PREREQ
