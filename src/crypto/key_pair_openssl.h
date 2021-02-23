// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair.h"
#include "openssl_wrappers.h"

#include <openssl/evp.h>
#include <stdexcept>
#include <string>

namespace crypto
{
  namespace
  {
    inline void OPENSSL_CHECK1(int rc)
    {
      unsigned long ec = ERR_get_error();
      if (rc != 1 && ec != 0)
      {
        throw std::runtime_error(
          fmt::format("OpenSSL error: {}", ERR_error_string(ec, NULL)));
      }
    }

    inline void OPENSSL_CHECKNULL(void* ptr)
    {
      if (ptr == NULL)
      {
        throw std::runtime_error("OpenSSL error: missing object");
      }
    }
  }

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

    static std::string error_string(int ec);
  };

  class KeyPair_OpenSSL : public PublicKey_OpenSSL, public KeyPair
  {
  public:
    KeyPair_OpenSSL(CurveID curve_id);
    KeyPair_OpenSSL(const KeyPair_OpenSSL&) = delete;
    KeyPair_OpenSSL(const Pem& pem, CBuffer pw = nullb);
    virtual ~KeyPair_OpenSSL() = default;

    virtual Pem private_key_pem() const override;
    virtual Pem public_key_pem() const override;

    using PublicKey_OpenSSL::verify;

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
