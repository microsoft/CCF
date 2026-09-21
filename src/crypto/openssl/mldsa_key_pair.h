// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include "ccf/crypto/mldsa_key_pair.h"
#  include "crypto/openssl/mldsa_public_key.h"

namespace ccf::crypto
{
  class MLDSAKeyPair_OpenSSL : public MLDSAPublicKey_OpenSSL,
                               public MLDSAKeyPair
  {
  public:
    explicit MLDSAKeyPair_OpenSSL(MLDSAParameterSet parameter_set);
    explicit MLDSAKeyPair_OpenSSL(
      const Pem& pem, std::optional<MLDSAParameterSet> expected = std::nullopt);
    explicit MLDSAKeyPair_OpenSSL(
      std::span<const uint8_t> der,
      std::optional<MLDSAParameterSet> expected = std::nullopt);
    ~MLDSAKeyPair_OpenSSL() override = default;

    [[nodiscard]] MLDSAParameterSet get_parameter_set() const override;

    [[nodiscard]] Pem private_key_pem() const override;
    [[nodiscard]] std::vector<uint8_t> private_key_der() const override;

    [[nodiscard]] Pem public_key_pem() const override;
    [[nodiscard]] std::vector<uint8_t> public_key_der() const override;

    [[nodiscard]] std::vector<uint8_t> sign(
      std::span<const uint8_t> contents,
      std::span<const uint8_t> context = {}) const override;

    [[nodiscard]] bool verify(
      std::span<const uint8_t> contents,
      std::span<const uint8_t> signature,
      std::span<const uint8_t> context = {}) override;
  };
}

#endif // OPENSSL_VERSION_PREREQ
