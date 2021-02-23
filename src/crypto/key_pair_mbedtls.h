// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair.h"
#include "mbedtls_wrappers.h"
#include "san.h"

namespace crypto
{
  class PublicKey_mbedTLS : public PublicKey
  {
  protected:
    mbedtls::PKContext ctx = mbedtls::make_unique<mbedtls::PKContext>();
    PublicKey_mbedTLS();
    CurveID get_curve_id() const;

  public:
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

    mbedtls_pk_context* get_raw_context() const;

    static std::string error_string(int err);
  };

  class KeyPair_mbedTLS : public PublicKey_mbedTLS, public KeyPair
  {
  public:
    KeyPair_mbedTLS(CurveID cid);
    KeyPair_mbedTLS(const Pem& pem, CBuffer pw = nullb);
    KeyPair_mbedTLS(mbedtls::PKContext&& k);
    KeyPair_mbedTLS(const KeyPair_mbedTLS&) = delete;
    virtual ~KeyPair_mbedTLS() = default;

    virtual Pem private_key_pem() const override;
    virtual Pem public_key_pem() const override;

    using PublicKey_mbedTLS::verify;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) override;

    virtual std::vector<uint8_t> sign(
      CBuffer d, MDType md_type = {}) const override;

    int sign(
      CBuffer d, size_t* sig_size, uint8_t* sig, MDType md_type = {}) const;

    std::vector<uint8_t> sign_hash(
      const uint8_t* hash, size_t hash_size) const override;

    virtual int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig) const override;

    virtual Pem create_csr(const std::string& name) const override;

    virtual Pem sign_csr(
      const Pem& issuer_cert,
      const Pem& signing_request,
      const std::vector<SubjectAltName> subject_alt_names,
      bool ca = false) const override;
  };
}
