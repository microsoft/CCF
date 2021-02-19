// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "pem.h"

namespace tls
{
  static constexpr size_t max_pem_key_size = 2048;

  static inline void hexdump(
    const char* name, const uint8_t* bytes, size_t size)
  {
    printf("%s: ", name);
    for (size_t i = 0; i < size; i++)
      printf("%02x", bytes[i]);
    printf("\n");
  }

  class PublicKeyBase
  {
  public:
    virtual CurveID get_curve_id() const = 0;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type,
      HashBytes& bytes) = 0;

    /**
     * Verify that a signature was produced on contents with the private key
     * associated with the public key held by the object.
     *
     * @param contents address of contents
     * @param contents_size size of contents
     * @param sig address of signature
     * @param sig_size size of signature
     * @param md_type Digest algorithm to use. Derived from the public key if
     * MDType::None.
     *
     * @return Whether the signature matches the contents and the key
     */
    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type = MDType::NONE)
    {
      HashBytes hash;
      return verify(contents, contents_size, sig, sig_size, md_type, hash);
    }

    /**
     * Verify that a signature was produced on contents with the private key
     * associated with the public key held by the object.
     *
     * @param contents Sequence of bytes that was signed
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the contents and the key
     */
    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature)
    {
      return verify(
        contents.data(), contents.size(), signature.data(), signature.size());
    }

    virtual bool verify_hash(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature,
      MDType md_type)
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size(), md_type);
    }

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type) = 0;

    /**
     * Get the public key in PEM format
     */
    virtual Pem public_key_pem() const = 0;
  };

  class KeyPairBase
  {
  public:
    virtual ~KeyPairBase() = default;

    virtual Pem private_key_pem() const = 0;

    virtual Pem public_key_pem() const = 0;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) = 0;

    virtual std::vector<uint8_t> sign_hash(
      const uint8_t* hash, size_t hash_size) const = 0;

    virtual int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig) const = 0;

    virtual std::vector<uint8_t> sign(CBuffer d, MDType md_type = {}) const = 0;

    virtual Pem create_csr(const std::string& name) const = 0;

    virtual Pem sign_csr(
      const Pem& issuer_cert,
      const Pem& signing_request,
      const std::vector<SubjectAltName> subject_alt_names,
      bool ca = false) const = 0;

    Pem self_sign(
      const std::string& name,
      const std::optional<SubjectAltName> subject_alt_name = std::nullopt,
      bool ca = true) const
    {
      std::vector<SubjectAltName> sans;
      if (subject_alt_name.has_value())
        sans.push_back(subject_alt_name.value());
      auto csr = create_csr(name);
      return sign_csr(Pem(0), csr, sans, ca);
    }

    Pem self_sign(
      const std::string& name,
      const std::vector<SubjectAltName> subject_alt_names,
      bool ca = true) const
    {
      auto csr = create_csr(name);
      return sign_csr(Pem(0), csr, subject_alt_names, ca);
    }
  };
}