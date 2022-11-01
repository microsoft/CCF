// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/public_key.h"
#include "crypto/openssl/public_key.h"
#include "openssl_wrappers.h"

#include <optional>
#include <stdexcept>
#include <string>

namespace crypto
{
  class KeyPair_OpenSSL : public PublicKey_OpenSSL, public KeyPair
  {
  public:
    KeyPair_OpenSSL(CurveID curve_id);
    KeyPair_OpenSSL(const KeyPair_OpenSSL&) = delete;
    KeyPair_OpenSSL(const Pem& pem);
    virtual ~KeyPair_OpenSSL() = default;

    virtual Pem private_key_pem() const override;
    virtual Pem public_key_pem() const override;
    virtual std::vector<uint8_t> public_key_der() const override;
    virtual std::vector<uint8_t> private_key_der() const override;

    using PublicKey_OpenSSL::verify;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) override;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size) override;

    virtual std::vector<uint8_t> sign(
      std::span<const uint8_t> d, MDType md_type = {}) const override;

    int sign(
      std::span<const uint8_t> d,
      size_t* sig_size,
      uint8_t* sig,
      MDType md_type = {}) const;

    static std::vector<uint8_t> sign(
      const std::vector<uint8_t>& data,
      const Pem& private_key,
      MDType md_type = MDType::NONE);

    std::vector<uint8_t> sign_hash(
      const uint8_t* hash, size_t hash_size) const override;

    static std::vector<uint8_t> sign_hash(
      const uint8_t* hash, size_t hash_size, EVP_PKEY* key);

    virtual int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig) const override;

    static int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig,
      EVP_PKEY* key);

    virtual Pem create_csr(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names,
      const std::optional<Pem>& public_key = std::nullopt) const override;

    virtual std::vector<uint8_t> create_csr_der(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names,
      const std::optional<Pem>& public_key = std::nullopt) const override;

    virtual Pem sign_csr_impl(
      const std::optional<Pem>& issuer_cert,
      const Pem& signing_request,
      const std::string& valid_from,
      const std::string& valid_to,
      bool ca = false,
      Signer signer = Signer::SUBJECT) const override;

    virtual std::vector<uint8_t> derive_shared_secret(
      const PublicKey& peer_key) override;

    virtual CurveID get_curve_id() const override;

    virtual std::vector<uint8_t> public_key_raw() const override;

    virtual PublicKey::Coordinates coordinates() const override;

    virtual JsonWebKeyECPrivate private_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const override;

  protected:
    OpenSSL::Unique_X509_REQ create_req(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names,
      const std::optional<Pem>& public_key) const;
  };
}
