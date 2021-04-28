// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../public_key.h"

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
    CurveID get_curve_id() const;

  public:
    PublicKey_OpenSSL(PublicKey_OpenSSL&& key) = default;
    PublicKey_OpenSSL(EVP_PKEY* key);
    PublicKey_OpenSSL(const Pem& pem);
    PublicKey_OpenSSL(const std::vector<uint8_t>& der);
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
  };
}
