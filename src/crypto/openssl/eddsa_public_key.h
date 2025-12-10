// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/eddsa_public_key.h"
#include "crypto/openssl/ec_public_key.h"
#include "crypto/openssl/hash.h"

#include <optional>
#include <string>
#include <vector>

namespace ccf::crypto
{
  class EdDSAPublicKey_OpenSSL : public EdDSAPublicKey
  {
  protected:
    EVP_PKEY* key = nullptr;

  public:
    EdDSAPublicKey_OpenSSL() = default;
    EdDSAPublicKey_OpenSSL(const Pem& pem);
    EdDSAPublicKey_OpenSSL(const JsonWebKeyEdDSAPublic& jwk);
    ~EdDSAPublicKey_OpenSSL() override;

    [[nodiscard]] Pem public_key_pem() const override;

    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t signature_size) override;

    static int get_openssl_group_id(CurveID gid);

    [[nodiscard]] CurveID get_curve_id() const override;

    [[nodiscard]] JsonWebKeyEdDSAPublic public_key_jwk_eddsa(
      const std::optional<std::string>& kid = std::nullopt) const override;
  };
}
