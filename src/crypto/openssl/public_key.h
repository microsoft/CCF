// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/public_key.h"
#include "openssl_wrappers.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>

namespace crypto
{
  class PublicKey_OpenSSL : public PublicKey
  {
  protected:
    EVP_PKEY* key = nullptr;
    PublicKey_OpenSSL();

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    std::vector<uint8_t> ec_point_public_from_jwk(
      const JsonWebKeyECPublic& jwk);
#else
    OpenSSL::Unique_EC_KEY ec_key_public_from_jwk(
      const JsonWebKeyECPublic& jwk);
#endif

  public:
    PublicKey_OpenSSL(PublicKey_OpenSSL&& key) = default;
    PublicKey_OpenSSL(EVP_PKEY* key);
    PublicKey_OpenSSL(const Pem& pem);
    PublicKey_OpenSSL(const std::vector<uint8_t>& der);
    PublicKey_OpenSSL(const JsonWebKeyECPublic& jwk);
    virtual ~PublicKey_OpenSSL();

    using PublicKey::verify;
    using PublicKey::verify_hash;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type,
      HashBytes& bytes) override;

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type) override;

    virtual Pem public_key_pem() const override;
    virtual std::vector<uint8_t> public_key_der() const override;
    virtual std::vector<uint8_t> public_key_raw() const override;

    virtual CurveID get_curve_id() const override;

    int get_openssl_group_id() const;
    static int get_openssl_group_id(CurveID gid);

    operator EVP_PKEY*() const
    {
      return key;
    }

    virtual Coordinates coordinates() const override;

    virtual JsonWebKeyECPublic public_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const override;
  };

  OpenSSL::Unique_PKEY key_from_raw_ec_point(
    const std::vector<uint8_t>& raw, int nid);
}
