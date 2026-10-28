// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/csr.h"
#include "ccf/crypto/mldsa_parameter_set.h"
#include "ccf/crypto/mldsa_public_key.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/san.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ccf::crypto
{
  /**
   * ML-DSA key-pair interface backed by the configured OpenSSL providers.
   */
  class MLDSAKeyPair
  {
  public:
    virtual ~MLDSAKeyPair() = default;

    [[nodiscard]] virtual MLDSAParameterSet get_parameter_set() const = 0;

    /**
     * Export an unencrypted PKCS#8 private key using the configured provider's
     * encoder, which selects the RFC 9881 private-key form. The returned Pem
     * and vector contain plaintext secrets in ordinary caller-owned memory.
     * Callers are responsible for protecting and erasing exported keys and
     * their copies.
     */
    [[nodiscard]] virtual Pem private_key_pem() const = 0;
    [[nodiscard]] virtual std::vector<uint8_t> private_key_der() const = 0;

    /// Export a SubjectPublicKeyInfo public key.
    [[nodiscard]] virtual Pem public_key_pem() const = 0;
    [[nodiscard]] virtual std::vector<uint8_t> public_key_der() const = 0;

    /// Export the FIPS 204 encoded public key.
    [[nodiscard]] virtual std::vector<uint8_t> public_key_raw() const = 0;

    /**
     * Sign contents with pure ML-DSA over the supplied message bytes.
     * Context is an optional domain-separation string of at most 255 bytes.
     * Provider errors, including rejected contexts, throw exceptions.
     */
    [[nodiscard]] virtual std::vector<uint8_t> sign(
      std::span<const uint8_t> contents,
      std::span<const uint8_t> context = {}) const = 0;

    /// Invalid signatures return false; provider errors throw.
    [[nodiscard]] virtual bool verify(
      std::span<const uint8_t> contents,
      std::span<const uint8_t> signature,
      std::span<const uint8_t> context = {}) = 0;

    using Signer = CSRSigner;

    /// PKCS#10 request for this key, or for public_key (SPKI PEM) when given,
    /// signed with pure ML-DSA. Subject name is "K=V,K=V", e.g. "CN=CCF Node".
    [[nodiscard]] virtual Pem create_csr(
      const std::string& subject_name,
      const std::vector<SubjectAltName>& subject_alt_names = {},
      const std::optional<Pem>& public_key = std::nullopt) const = 0;

    /// As above, with the subject name as a DER-encoded X.501 Name. Throws
    /// std::invalid_argument unless subject_name_der is exactly one Name.
    [[nodiscard]] virtual Pem create_csr(
      const std::vector<uint8_t>& subject_name_der,
      const std::vector<SubjectAltName>& subject_alt_names = {},
      const std::optional<Pem>& public_key = std::nullopt) const = 0;

  private:
    [[nodiscard]] virtual Pem sign_csr_impl(
      const std::optional<Pem>& issuer_cert,
      const Pem& signing_request,
      const std::string& valid_from,
      const std::string& valid_to,
      bool ca,
      Signer signer) const = 0;

  public:
    /**
     * X.509 certificate for signing_request, issued under issuer_cert with
     * pure ML-DSA; the request signature is verified with the key of signer.
     * Times are "YYYYMMDDHHMMSSZ". Throws std::logic_error on an invalid
     * validity period, std::runtime_error on other invalid input or
     * provider failures.
     */
    [[nodiscard]] Pem sign_csr(
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

    /// Self-signed X.509 certificate for this key, a CA by default. Times are
    /// "YYYYMMDDHHMMSSZ". Throws std::logic_error on an invalid validity
    /// period, std::runtime_error on other invalid input or provider failures.
    [[nodiscard]] Pem self_sign(
      const std::string& subject_name,
      const std::string& valid_from,
      const std::string& valid_to,
      const std::vector<SubjectAltName>& subject_alt_names = {},
      bool ca = true) const
    {
      return sign_csr_impl(
        std::nullopt,
        create_csr(subject_name, subject_alt_names),
        valid_from,
        valid_to,
        ca,
        Signer::SUBJECT);
    }

    /// As above, with the subject name as a DER-encoded X.501 Name.
    [[nodiscard]] Pem self_sign(
      const std::vector<uint8_t>& subject_name_der,
      const std::string& valid_from,
      const std::string& valid_to,
      const std::vector<SubjectAltName>& subject_alt_names = {},
      bool ca = true) const
    {
      return sign_csr_impl(
        std::nullopt,
        create_csr(subject_name_der, subject_alt_names),
        valid_from,
        valid_to,
        ca,
        Signer::SUBJECT);
    }
  };

  using MLDSAKeyPairPtr = std::shared_ptr<MLDSAKeyPair>;

  /// Generate a key pair with an explicitly selected parameter set.
  /// Throws std::invalid_argument for an unknown parameter set.
  MLDSAKeyPairPtr make_mldsa_key_pair(MLDSAParameterSet parameter_set);

  /**
   * Import an unencrypted PKCS#8 private key in any RFC 9881 form decoded by
   * the configured providers, inferring its parameter set. Prefer the pinned
   * overloads when the required set is known.
   * Import factories throw std::invalid_argument for key material the
   * configured providers reject, and std::runtime_error for provider
   * failures.
   */
  MLDSAKeyPairPtr make_mldsa_key_pair(const Pem& pem);
  /// DER import with the same exception contract as PEM import.
  MLDSAKeyPairPtr make_mldsa_key_pair(std::span<const uint8_t> der);

  /**
   * Import with an expected parameter set for a trust anchor or identity.
   * A mismatch throws std::invalid_argument once the key is decoded. Other
   * import errors have the same contract as unpinned import.
   */
  MLDSAKeyPairPtr make_mldsa_key_pair(
    const Pem& pem, MLDSAParameterSet expected);
  /// Pinned DER import with the same contract as pinned PEM import.
  MLDSAKeyPairPtr make_mldsa_key_pair(
    std::span<const uint8_t> der, MLDSAParameterSet expected);
}
