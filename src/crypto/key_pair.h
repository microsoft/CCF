// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "curve.h"
#include "hash.h"
#include "pem.h"
#include "san.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace crypto
{
  class PublicKey
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

  class KeyPair
  {
  public:
    virtual ~KeyPair() = default;

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

  using PublicKeyPtr = std::shared_ptr<PublicKey>;
  using KeyPairPtr = std::shared_ptr<KeyPair>;

  /**
   * Construct PublicKey from a raw public key in PEM format
   *
   * @param public_pem Sequence of bytes containing the key in PEM format
   */
  PublicKeyPtr make_public_key(const Pem& pem);

  /**
   * Construct PublicKey from a raw public key in DER format
   *
   * @param public_der Sequence of bytes containing the key in DER format
   */
  PublicKeyPtr make_public_key(const std::vector<uint8_t> der);

  /**
   * Create a new public / private ECDSA key pair on specified curve and
   * implementation
   */
  KeyPairPtr make_key_pair(CurveID curve_id = service_identity_curve_choice);

  /**
   * Create a public / private ECDSA key pair from existing private key data
   */
  KeyPairPtr make_key_pair(const Pem& pkey, CBuffer pw = nullb);
}
