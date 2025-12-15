// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/ec_public_key.h"

#include <optional>
#include <stdexcept>
#include <string>

namespace ccf::crypto
{
  class ECKeyPair_OpenSSL : public ECPublicKey_OpenSSL, public ECKeyPair
  {
  public:
    ECKeyPair_OpenSSL(CurveID curve_id);
    ECKeyPair_OpenSSL(const ECKeyPair_OpenSSL&) = delete;
    ECKeyPair_OpenSSL(const Pem& pem);
    ECKeyPair_OpenSSL(const JsonWebKeyECPrivate& jwk);
    ~ECKeyPair_OpenSSL() override = default;

    [[nodiscard]] Pem private_key_pem() const override;
    [[nodiscard]] Pem public_key_pem() const override;
    [[nodiscard]] std::vector<uint8_t> public_key_der() const override;
    [[nodiscard]] std::vector<uint8_t> private_key_der() const override;

    using ECPublicKey_OpenSSL::verify;

    bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature) override;

    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size) override;

    [[nodiscard]] std::vector<uint8_t> sign(
      std::span<const uint8_t> d, MDType md_type = {}) const override;

    int sign(
      std::span<const uint8_t> d,
      size_t* sig_size,
      uint8_t* sig,
      MDType md_type = {}) const;

    std::vector<uint8_t> sign_hash(
      const uint8_t* hash, size_t hash_size) const override;

    int sign_hash(
      const uint8_t* hash,
      size_t hash_size,
      size_t* sig_size,
      uint8_t* sig) const override;

    [[nodiscard]] Pem create_csr(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names,
      const std::optional<Pem>& public_key = std::nullopt) const override;

    [[nodiscard]] std::vector<uint8_t> create_csr_der(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names,
      const std::optional<Pem>& public_key = std::nullopt) const override;

    [[nodiscard]] Pem sign_csr_impl(
      const std::optional<Pem>& issuer_cert,
      const Pem& signing_request,
      const std::string& valid_from,
      const std::string& valid_to,
      bool ca = false,
      Signer signer = Signer::SUBJECT) const override;

    std::vector<uint8_t> derive_shared_secret(
      const ECPublicKey& peer_key) override;

    [[nodiscard]] CurveID get_curve_id() const override;

    [[nodiscard]] std::vector<uint8_t> public_key_raw() const override;

    [[nodiscard]] ECPublicKey::Coordinates coordinates() const override;

    [[nodiscard]] JsonWebKeyECPrivate private_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const override;

  protected:
    [[nodiscard]] OpenSSL::Unique_X509_REQ create_req(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names,
      const std::optional<Pem>& public_key) const;
  };
}
