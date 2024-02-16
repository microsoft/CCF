// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/jwk.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/public_key.h"
#include "ccf/crypto/san.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace crypto
{
  class KeyPair
  {
  public:
    virtual ~KeyPair() = default;

    virtual Pem private_key_pem() const = 0;
    virtual Pem public_key_pem() const = 0;
    virtual std::vector<uint8_t> public_key_der() const = 0;
    virtual std::vector<uint8_t> private_key_der() const = 0;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) = 0;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size) = 0;

    virtual std::vector<uint8_t> sign_hash(
      const uint8_t* hash, size_t hash_size) const = 0;

    virtual int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig) const = 0;

    virtual std::vector<uint8_t> sign(
      std::span<const uint8_t> d, MDType md_type = {}) const = 0;

    virtual Pem create_csr(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names,
      const std::optional<Pem>& public_key = std::nullopt) const = 0;

    Pem create_csr(const std::string& subject_name) const
    {
      return create_csr(subject_name, {});
    }

    virtual std::vector<uint8_t> create_csr_der(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names,
      const std::optional<Pem>& public_key = std::nullopt) const = 0;

    // Note about the signed_by_issuer parameter to sign_csr: when issuing a new
    // certificate for an old subject, which does not exist anymore, we cannot
    // sign the CSR with that old subject's private key. Instead, the issuer
    // signs the CSR itself, which is slightly unusal. Instead, we could also
    // ask the subject to produce a CSR right after it becomes alive and keep it
    // around until we need it, but those complications are not stricly
    // necessary. In our case, we use this to re-endorse previous service
    // identities, which are self-signed, and replace them with new endorsements
    // by the current service identity (which doesn't have the private key of
    // previous ones).

    enum class Signer
    {
      SUBJECT = 0,
      ISSUER = 1
    };

  private:
    virtual Pem sign_csr_impl(
      const std::optional<Pem>& issuer_cert,
      const Pem& signing_request,
      const std::string& valid_from,
      const std::string& valid_to,
      bool ca = false,
      Signer signer = Signer::SUBJECT) const = 0;

  public:
    virtual Pem sign_csr(
      const Pem& issuer_cert,
      const Pem& signing_request,
      const std::string& valid_from,
      const std::string& valid_to,
      bool ca = false,
      Signer signer = Signer::SUBJECT) const
    {
      return sign_csr_impl(
        issuer_cert, signing_request, valid_from, valid_to, ca, signer);
    }

    Pem self_sign(
      const std::string& name,
      const std::string& valid_from,
      const std::string& valid_to,
      const std::optional<SubjectAltName> subject_alt_name = std::nullopt,
      bool ca = true) const
    {
      std::vector<SubjectAltName> sans;
      if (subject_alt_name.has_value())
      {
        sans.push_back(subject_alt_name.value());
      }
      auto csr = create_csr(name, sans);
      return sign_csr_impl(std::nullopt, csr, valid_from, valid_to, ca);
    }

    Pem self_sign(
      const std::string& subject_name,
      const std::string& valid_from,
      const std::string& valid_to,
      const std::vector<SubjectAltName>& subject_alt_names,
      bool ca = true) const
    {
      auto csr = create_csr(subject_name, subject_alt_names);
      return sign_csr_impl(std::nullopt, csr, valid_from, valid_to, ca);
    }

    virtual std::vector<uint8_t> derive_shared_secret(
      const PublicKey& peer_key) = 0;

    virtual std::vector<uint8_t> public_key_raw() const = 0;

    virtual CurveID get_curve_id() const = 0;

    virtual PublicKey::Coordinates coordinates() const = 0;

    virtual JsonWebKeyECPrivate private_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const = 0;
  };

  using PublicKeyPtr = std::shared_ptr<PublicKey>;
  using KeyPairPtr = std::shared_ptr<KeyPair>;

  /**
   * Construct PublicKey from a raw public key in PEM format
   *
   * @param pem Sequence of bytes containing the key in PEM format
   * @return Public key
   */
  PublicKeyPtr make_public_key(const Pem& pem);

  /**
   * Construct PublicKey from a raw public key in DER format
   *
   * @param der Sequence of bytes containing the key in DER format
   * @return Public key
   */
  PublicKeyPtr make_public_key(const std::vector<uint8_t>& der);

  /**
   * Construct PublicKey from a JsonWebKeyECPublic object
   *
   * @param jwk JsonWebKeyECPublic object
   * @return Public key
   */
  PublicKeyPtr make_public_key(const JsonWebKeyECPublic& jwk);

  /**
   * Create a new public / private ECDSA key pair on specified curve and
   * implementation
   *
   * @param curve_id Elliptic curve to use
   * @return Key pair
   */
  KeyPairPtr make_key_pair(CurveID curve_id = service_identity_curve_choice);

  /**
   * Create a public / private ECDSA key pair from existing private key data
   *
   * @param pkey PEM key to load
   * @return Key pair
   */
  KeyPairPtr make_key_pair(const Pem& pkey);

  /**
   * Construct a new public / private ECDSA key pair from a JsonWebKeyECPrivate
   * object
   *
   * @param jwk JsonWebKeyECPrivate object
   * @return Key pair
   */
  KeyPairPtr make_key_pair(const JsonWebKeyECPrivate& jwk);
}
