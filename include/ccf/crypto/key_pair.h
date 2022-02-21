// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/public_key.h"
#include "ccf/crypto/san.h"
#include "ccf/ds/buffer.h"

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

    virtual std::vector<uint8_t> sign(CBuffer d, MDType md_type = {}) const = 0;

    virtual Pem create_csr(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names) const = 0;

    Pem create_csr(const std::string& subject_name) const
    {
      return create_csr(subject_name, {});
    }

    virtual Pem sign_csr(
      const Pem& issuer_cert,
      const Pem& signing_request,
      const std::string& valid_from,
      const std::string& valid_to,
      bool ca = false) const = 0;

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
      return sign_csr(Pem(0), csr, valid_from, valid_to, ca);
    }

    Pem self_sign(
      const std::string& subject_name,
      const std::string& valid_from,
      const std::string& valid_to,
      const std::vector<SubjectAltName>& subject_alt_names,
      bool ca = true) const
    {
      auto csr = create_csr(subject_name, subject_alt_names);
      return sign_csr(Pem(0), csr, valid_from, valid_to, ca);
    }

    virtual std::vector<uint8_t> derive_shared_secret(
      const PublicKey& peer_key) = 0;

    virtual std::vector<uint8_t> public_key_raw() const = 0;

    virtual CurveID get_curve_id() const = 0;
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
   * @param pw Password
   * @return Key pair
   */
  KeyPairPtr make_key_pair(const Pem& pkey, CBuffer pw = nullb);
}
