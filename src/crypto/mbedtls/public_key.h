// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../public_key.h"
#include "../san.h"
#include "mbedtls_wrappers.h"

namespace crypto
{
  class PublicKey_mbedTLS : public PublicKey
  {
  protected:
    mbedtls::PKContext ctx = mbedtls::make_unique<mbedtls::PKContext>();
    PublicKey_mbedTLS();
    CurveID get_curve_id() const;

  public:
    static constexpr size_t max_pem_key_size = 2048;
    static constexpr size_t max_der_key_size = 2048;

    PublicKey_mbedTLS(PublicKey_mbedTLS&& pk) = default;
    PublicKey_mbedTLS(mbedtls::PKContext&& c);
    PublicKey_mbedTLS(const Pem& pem);
    PublicKey_mbedTLS(const std::vector<uint8_t>& der);
    virtual ~PublicKey_mbedTLS() = default;

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

    mbedtls_pk_context* get_raw_context() const;
  };
}
