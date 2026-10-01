// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_public_key.h"
#include "ccf/crypto/rsa_public_key.h"
#include "ccf/crypto/sha256_hash.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

namespace ccf::crypto
{
  /// COSE key types, from the IANA "COSE Key Types" registry.
  enum class COSEKeyType : uint8_t
  {
    EC2 = 2,
    RSA = 3,
  };

  /**
   * A public key that verifies COSE_Sign1 signatures, as carried in a COSE_Key
   * (RFC 9052 Section 7): an EC2 key on P-256, P-384 or P-521 (RFC 9053
   * Section 7.1.1), or an RSA key (RFC 8230 Section 4).
   *
   * The key parameters, the encoding and the RFC 9679 thumbprint are derived
   * from the key on each call, so callers that use them repeatedly should keep
   * the result, for example by kid. Pass the key to
   * ccf::crypto::make_cose_verifier_from_key() to verify signatures.
   */
  class COSEKey
  {
  public:
    /// EC2 key parameters.
    struct EC2Parameters
    {
      /// COSE curve: 1 (P-256), 2 (P-384) or 3 (P-521)
      int64_t crv = 0;
      /// x-coordinate, of the curve's field size
      std::vector<uint8_t> x;
      /// y-coordinate, of the curve's field size
      std::vector<uint8_t> y;
    };

    /// RSA key parameters, big-endian without leading zero octets.
    struct RSAParameters
    {
      /// Modulus
      std::vector<uint8_t> n;
      /// Public exponent
      std::vector<uint8_t> e;
    };

    /**
     * @throws std::invalid_argument if key is null
     * @throws std::runtime_error if the curve is not P-256, P-384 or P-521
     */
    explicit COSEKey(ECPublicKeyPtr key);

    /**
     * @throws std::invalid_argument if key is null
     * @throws std::runtime_error if the modulus is not 2048 to 16384 bits
     * long, or the public exponent is not odd, at least 3 and at most 64 bits
     * long.
     */
    explicit COSEKey(RSAPublicKeyPtr key);

    /**
     * Parse an encoded COSE_Key, which may be untrusted.
     *
     * Only public keys are accepted: EC2 keys whose coordinates have the
     * curve's field size and form a point on the curve, and RSA keys of 2048
     * to 16384 bits whose public exponent is odd, at least 3 and at most 64
     * bits long. Compressed points, and RSA parameters with leading zero
     * octets, are rejected, so that each key has a single encoding and
     * thumbprint. "alg", if present, must be an algorithm that CCF can verify
     * with the key, and "key_ops", if present, must allow verify. "kid" is not
     * retained, and unknown labels are ignored.
     *
     * @throws std::invalid_argument if cose_key is malformed or unsupported
     */
    [[nodiscard]] static COSEKey from_cbor(std::span<const uint8_t> cose_key);

    /**
     * The public key of a DER X.509 certificate, which may be untrusted. An
     * RSA key must meet the same requirements as in from_cbor().
     *
     * @throws std::invalid_argument if the certificate cannot be parsed, or its
     * key is not supported
     */
    [[nodiscard]] static COSEKey from_der_cert(std::span<const uint8_t> der);

    [[nodiscard]] COSEKeyType kty() const;

    /**
     * The "alg" of a parsed COSE_Key, if any. Verifiers made from this key
     * reject every other algorithm (RFC 9052 Section 7.1).
     */
    [[nodiscard]] std::optional<int64_t> alg() const;

    /// The key parameters, or std::nullopt if kty() is not EC2.
    [[nodiscard]] std::optional<EC2Parameters> ec2_parameters() const;

    /// The key parameters, or std::nullopt if kty() is not RSA.
    [[nodiscard]] std::optional<RSAParameters> rsa_parameters() const;

    /// The key, or nullptr if kty() is not EC2.
    [[nodiscard]] ECPublicKeyPtr ec_public_key() const;

    /// The key, or nullptr if kty() is not RSA.
    [[nodiscard]] RSAPublicKeyPtr rsa_public_key() const;

    /**
     * Deterministically encoded COSE_Key (RFC 8949 Section 4.2.1), with kty,
     * the key parameters, and alg if set.
     */
    [[nodiscard]] std::vector<uint8_t> to_cbor() const;

    /**
     * As to_cbor(), with a key identifier.
     *
     * @param kid Key identifier, encoded as a byte string
     */
    [[nodiscard]] std::vector<uint8_t> to_cbor(
      std::span<const uint8_t> kid) const;

    /**
     * As to_cbor(), with a key identifier.
     *
     * @param kid Key identifier, whose bytes are encoded as a byte string
     */
    [[nodiscard]] std::vector<uint8_t> to_cbor(std::string_view kid) const;

    /// COSE Key Thumbprint (RFC 9679) with SHA-256.
    [[nodiscard]] Sha256Hash thumbprint_sha256() const;

  private:
    using PublicKey = std::variant<ECPublicKeyPtr, RSAPublicKeyPtr>;

    COSEKey(PublicKey public_key_, std::optional<int64_t> alg_);

    PublicKey public_key;
    std::optional<int64_t> key_alg;
  };
}
