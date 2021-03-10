// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "hash.h"
#include "key_pair.h"
#include "pem.h"
#include "public_key.h"

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

    virtual Pem public_key_pem() const
    {
      return public_key->public_key_pem();
    }

    virtual std::vector<uint8_t> public_key_der() const
    {
      return public_key->public_key_der();
    }
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
  std::vector<uint8_t> cert_pem_to_der(const Pem& pem);

  std::vector<uint8_t> public_key_der_from_cert(
    const std::vector<uint8_t>& der);

  void check_is_cert(const CBuffer& der);
}
