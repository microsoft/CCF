// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include "ccf/crypto/mldsa_parameter_set.h"
#  include "ccf/crypto/mldsa_public_key.h"
#  include "ccf/crypto/pem.h"

#  include <cstdint>
#  include <memory>
#  include <span>
#  include <vector>

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

    /**
     * Sign contents with pure ML-DSA over the supplied message bytes.
     * Context is an optional domain-separation string of at most 255 bytes.
     * Provider errors, including rejected contexts, throw exceptions.
     */
    [[nodiscard]] virtual std::vector<uint8_t> sign(
      std::span<const uint8_t> contents,
      std::span<const uint8_t> context = {}) const = 0;

    /// Invalid signatures return false; provider errors throw.
    virtual bool verify(
      std::span<const uint8_t> contents,
      std::span<const uint8_t> signature,
      std::span<const uint8_t> context = {}) = 0;
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
#endif // OPENSSL_VERSION_PREREQ
