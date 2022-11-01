// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/eddsa_key_pair.h"
#include "crypto/openssl/eddsa_public_key.h"
#include "openssl_wrappers.h"

namespace crypto
{
  class EdDSAKeyPair_OpenSSL : public EdDSAPublicKey_OpenSSL,
                               public EdDSAKeyPair
  {
  public:
    EdDSAKeyPair_OpenSSL(CurveID curve_id);

    Pem private_key_pem() const override;

    Pem public_key_pem() const override;

    std::vector<uint8_t> sign(std::span<const uint8_t> d) const override;

    static std::vector<uint8_t> sign(
      std::span<const uint8_t> d, const Pem& private_key);

    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size) override;
  };
}
