// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "curve.h"
#include "hash.h"
#include "key_pair.h"
#include "mbedtls_wrappers.h"
#include "pem.h"

#include <openssl/x509.h>

namespace crypto
{
  class Verifier
  {
  protected:
    std::shared_ptr<PublicKey> public_key;
    MDType md_type = MDType::NONE;

  public:
    Verifier() : public_key(nullptr) {}
    virtual ~Verifier() {}

    virtual std::vector<uint8_t> cert_der() = 0;
    virtual Pem cert_pem() = 0;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type) const
    {
      if (md_type == MDType::NONE)
        md_type = this->md_type;

      return public_key->verify(
        contents, contents_size, sig, sig_size, md_type);
    }

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type,
      HashBytes& hash_bytes) const
    {
      if (md_type == MDType::NONE)
        md_type = this->md_type;

      return public_key->verify(
        contents, contents_size, sig, sig_size, md_type, hash_bytes);
    }

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature,
      MDType md_type = MDType::NONE) const
    {
      return verify(
        contents.data(),
        contents.size(),
        signature.data(),
        signature.size(),
        md_type);
    }

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature,
      MDType md_type,
      HashBytes& hash_bytes) const
    {
      return verify(
        contents.data(),
        contents.size(),
        signature.data(),
        signature.size(),
        md_type,
        hash_bytes);
    }

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type = MDType::NONE)
    {
      if (md_type == MDType::NONE)
        md_type = this->md_type;

      return public_key->verify_hash(hash, hash_size, sig, sig_size, md_type);
    }

    virtual bool verify_hash(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature,
      MDType md_type = MDType::NONE)
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size(), md_type);
    }

    template <size_t SIZE>
    bool verify_hash(
      const std::array<uint8_t, SIZE>& hash,
      const std::vector<uint8_t>& signature,
      MDType md_type = MDType::NONE)
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size(), md_type);
    }

    virtual CurveID get_curve_id() const
    {
      return public_key->get_curve_id();
    }

    virtual Pem public_key_pem() const
    {
      return public_key->public_key_pem();
    }
  };

  class Verifier_mbedTLS : public Verifier
  {
  protected:
    mutable mbedtls::X509Crt cert;

    MDType get_md_type(mbedtls_md_type_t mdt) const;

  public:
    Verifier_mbedTLS(const std::vector<uint8_t>& c);
    Verifier_mbedTLS(const Verifier_mbedTLS&) = delete;
    virtual ~Verifier_mbedTLS() = default;

    virtual std::vector<uint8_t> cert_der() override;
    virtual Pem cert_pem() override;
  };

  class Verifier_OpenSSL : public Verifier
  {
  protected:
    mutable X509* cert;

    MDType get_md_type(int mdt) const;

  public:
    Verifier_OpenSSL(const std::vector<uint8_t>& c);
    Verifier_OpenSSL(Verifier_OpenSSL&& v) = default;
    Verifier_OpenSSL(const Verifier_OpenSSL&) = delete;
    virtual ~Verifier_OpenSSL();

    virtual std::vector<uint8_t> cert_der() override;
    virtual Pem cert_pem() override;
  };

  using VerifierPtr = std::shared_ptr<Verifier>;
  using VerifierUniquePtr = std::unique_ptr<Verifier>;

  /**
   * Construct Verifier from a certificate in DER or PEM format
   *
   * @param cert Sequence of bytes containing the certificate
   */
  VerifierUniquePtr make_unique_verifier(const std::vector<uint8_t>& cert);

  VerifierPtr make_verifier(const std::vector<uint8_t>& cert);

  VerifierUniquePtr make_unique_verifier(const Pem& pem);

  VerifierPtr make_verifier(const Pem& pem);

  crypto::Pem cert_der_to_pem(const std::vector<uint8_t>& der);

  std::vector<uint8_t> cert_pem_to_der(const std::string& pem_string);

  Pem public_key_pem_from_cert(const Pem& cert);

  void check_is_cert(const CBuffer& der);
}
