// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_PREREQ(3, 5)

#  include "ccf/crypto/mldsa_parameter_set.h"
#  include "ccf/crypto/pem.h"

#  include <cstdint>
#  include <memory>
#  include <span>
#  include <vector>

namespace ccf::crypto
{
  /**
   * ML-DSA public-key interface backed by the configured OpenSSL providers.
   */
  class MLDSAPublicKey
  {
  public:
    virtual ~MLDSAPublicKey() = default;

    [[nodiscard]] virtual MLDSAParameterSet get_parameter_set() const = 0;

    /// Export a SubjectPublicKeyInfo public key.
    [[nodiscard]] virtual Pem public_key_pem() const = 0;
    [[nodiscard]] virtual std::vector<uint8_t> public_key_der() const = 0;

    /**
     * Verify a pure ML-DSA signature over the supplied message bytes.
     * Context is an optional domain-separation string of at most 255 bytes.
     * Invalid signatures return false. Provider errors, including rejected
     * contexts, throw exceptions.
     */
    [[nodiscard]] virtual bool verify(
      std::span<const uint8_t> contents,
      std::span<const uint8_t> signature,
      std::span<const uint8_t> context = {}) = 0;
  };

  using MLDSAPublicKeyPtr = std::shared_ptr<MLDSAPublicKey>;

  /**
   * Import a SubjectPublicKeyInfo public key, inferring its parameter set.
   * Prefer the pinned overloads when the required set is known.
   * Import factories throw std::invalid_argument for key material the
   * configured providers reject, and std::runtime_error for provider
   * failures.
   */
  MLDSAPublicKeyPtr make_mldsa_public_key(const Pem& pem);
  /// DER import with the same exception contract as PEM import.
  MLDSAPublicKeyPtr make_mldsa_public_key(std::span<const uint8_t> der);

  /**
   * Import with an expected parameter set for a trust anchor or identity.
   * A mismatch throws std::invalid_argument once the key is decoded. Other
   * import errors have the same contract as unpinned import.
   */
  MLDSAPublicKeyPtr make_mldsa_public_key(
    const Pem& pem, MLDSAParameterSet expected);
  /// Pinned DER import with the same contract as pinned PEM import.
  MLDSAPublicKeyPtr make_mldsa_public_key(
    std::span<const uint8_t> der, MLDSAParameterSet expected);
}
#endif // OPENSSL_VERSION_PREREQ
