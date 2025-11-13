// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/hash_bytes.h"
#include "ccf/crypto/jwk.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/san.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ccf::crypto
{
  class ECPublicKey
  {
  public:
    virtual ~ECPublicKey() = default;

    /**
     * Verify that a signature was produced on contents with the private key
     * associated with the public key held by the object.
     *
     * @param contents address of contents
     * @param contents_size size of contents
     * @param sig address of signature
     * @param sig_size size of signature
     * @param md_type Digest algorithm to use
     * @param bytes Buffer to write the hash to
     *
     * @return Whether the signature matches the contents and the key
     */
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
     * @param md_type Digest algorithm to use (derived from the public key if
     * md_type == MDType::None).
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

    /**
     * Verify that a signature was produced on the hash of some contents with
     * the private key associated with the public key held by the object.
     *
     * @param hash Hash of some content
     * @param signature Signature as a sequence of bytes
     * @param md_type Type of hash
     *
     * @return Whether the signature matches the hash and the key
     */
    virtual bool verify_hash(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature,
      MDType md_type)
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size(), md_type);
    }

    /**
     * Verify that a signature was produced on the hash of some contents with
     * the private key associated with the public key held by the object.
     *
     * @param hash Hash of some content
     * @param hash_size length of @p hash
     * @param sig Signature as a sequence of bytes
     * @param sig_size Length of @p sig
     * @param md_type Digest algorithm
     *
     * @return Whether the signature matches the hash and the key
     */
    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type) = 0;

    /**
     * Get the public key in PEM format
     */
    [[nodiscard]] virtual Pem public_key_pem() const = 0;

    /**
     * Get the public key in DER format
     */
    [[nodiscard]] virtual std::vector<uint8_t> public_key_der() const = 0;

    /**
     * Get the raw bytes of the public key
     */
    [[nodiscard]] virtual std::vector<uint8_t> public_key_raw() const = 0;

    /**
     * The curve ID
     */
    [[nodiscard]] virtual CurveID get_curve_id() const = 0;

    struct Coordinates
    {
      std::vector<uint8_t> x;
      std::vector<uint8_t> y;
    };

    /**
     * The x/y coordinates of the public key
     */
    [[nodiscard]] virtual Coordinates coordinates() const = 0;

    [[nodiscard]] virtual JsonWebKeyECPublic public_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const = 0;
  };

  using ECPublicKeyPtr = std::shared_ptr<ECPublicKey>;

  /**
   * Construct ECPublicKey from a raw public key in PEM format
   *
   * @param pem Sequence of bytes containing the key in PEM format
   * @return Public key
   */
  ECPublicKeyPtr make_ec_public_key(const Pem& pem);

  /**
   * Construct ECPublicKey from a raw public key in DER format
   *
   * @param der Sequence of bytes containing the key in DER format
   * @return Public key
   */
  ECPublicKeyPtr make_ec_public_key(const std::vector<uint8_t>& der);

  /**
   * Construct ECPublicKey from a JsonWebKeyECPublic object
   *
   * @param jwk JsonWebKeyECPublic object
   * @return Public key
   */
  ECPublicKeyPtr make_ec_public_key(const JsonWebKeyECPublic& jwk);
}
