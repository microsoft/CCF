// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_public_key.h"
#include "ccf/crypto/jwk.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/rsa_public_key.h"

#include <chrono>

namespace ccf::crypto
{
  class Verifier
  {
  protected:
    std::variant<ccf::crypto::RSAPublicKeyPtr, ccf::crypto::ECPublicKeyPtr>
      public_key;

  public:
    Verifier() = default;
    virtual ~Verifier() = default;

    virtual std::vector<uint8_t> cert_der() = 0;
    virtual Pem cert_pem() = 0;

    /** Verify a signature
     * @param contents Contents over which the signature was generated
     * @param contents_size Size of @p contents
     * @param sig Signature
     * @param sig_size Size of @p sig
     * @param md_type Hash algorithm
     * @return Boolean indicating success
     */
    [[nodiscard]] virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type = MDType::NONE) const;

    /** Verify a signature
     * @param contents Contents over which the signature was generated
     * @param sig Signature
     * @param md_type Hash algorithm
     * @return Boolean indicating success
     */
    [[nodiscard]] virtual bool verify(
      std::span<const uint8_t> contents,
      std::span<const uint8_t> sig,
      MDType md_type = MDType::NONE) const
    {
      return verify(
        contents.data(), contents.size(), sig.data(), sig.size(), md_type);
    }

    /** Verify a signature
     * @param contents Contents over which the signature was generated
     * @param signature Signature
     * @param md_type Hash algorithm
     * @return Boolean indicating success
     */
    [[nodiscard]] virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature,
      MDType md_type = MDType::NONE) const
    {
      return verify(
        contents.data(),
        contents.size(),
        signature.data(),
        signature.size(),
        md_type);
    }

    /** Verify a signature over a hash
     * @param hash Hash over which the signature was generated
     * @param hash_size Size of @p hash
     * @param sig Signature
     * @param sig_size Size of @p sig
     * @param md_type Hash algorithm
     * @return Boolean indicating success
     */
    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type = MDType::NONE);

    /** Verify a signature over a hash
     * @param hash Hash over which the signature was generated
     * @param signature Signature
     * @param md_type Hash algorithm
     * @return Boolean indicating success
     */
    virtual bool verify_hash(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature,
      MDType md_type = MDType::NONE)
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size(), md_type);
    }

    /** Verify a signature over a hash
     * @param hash Hash over which the signature was generated
     * @param signature Signature
     * @param md_type Hash algorithm
     * @return Boolean indicating success
     */
    template <size_t SIZE>
    bool verify_hash(
      const std::array<uint8_t, SIZE>& hash,
      const std::vector<uint8_t>& signature,
      MDType md_type = MDType::NONE)
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size(), md_type);
    }

    /** Extract the public key of the certificate in PEM format
     * @return PEM encoded public key
     */
    virtual Pem public_key_pem() const;

    /** Extract the public key of the certificate in DER format
     * @return DER encoded public key
     */
    virtual std::vector<uint8_t> public_key_der() const;

    /** Verify the certificate (held internally)
     * @param trusted_certs Vector of trusted certificates
     * @param chain Vector of ordered untrusted certificates used to
     *  build a chain to trusted certificates
     * @param ignore_time Flag to disable certificate expiry checks
     * @return true if the verification is successful
     */
    virtual bool verify_certificate(
      const std::vector<const Pem*>& trusted_certs,
      const std::vector<const Pem*>& chain = {},
      bool ignore_time = false) = 0;

    /** Indicates whether the certificate (held intenally) is self-signed */
    [[nodiscard]] virtual bool is_self_signed() const = 0;

    /** The serial number of the certificate */
    [[nodiscard]] virtual std::string serial_number() const = 0;

    /** The validity period of the certificate */
    [[nodiscard]] virtual std::pair<std::string, std::string> validity_period()
      const = 0;

    /** The number of seconds of the validity period of the
     * certificate remaining */
    [[nodiscard]] virtual size_t remaining_seconds(
      const std::chrono::system_clock::time_point& now) const = 0;

    /** The percentage of the validity period of the certificate remaining */
    [[nodiscard]] virtual double remaining_percentage(
      const std::chrono::system_clock::time_point& now) const = 0;

    /** The subject name of the certificate */
    [[nodiscard]] virtual std::string subject() const = 0;
  };

  using VerifierPtr = std::shared_ptr<Verifier>;
  using VerifierUniquePtr = std::unique_ptr<Verifier>;

  /**
   * Construct Verifier from a certificate in DER or PEM format
   * @param cert The certificate containing a public key
   */
  VerifierUniquePtr make_unique_verifier(const std::vector<uint8_t>& cert);

  /** Construct a certificate verifier
   * @param cert The certificate containing a public key
   * @return A verifier
   */
  VerifierPtr make_verifier(const std::vector<uint8_t>& cert);

  /**
   * Construct Verifier from a certificate in PEM format
   * @param pem The certificate containing a public key
   */
  VerifierUniquePtr make_unique_verifier(const Pem& pem);

  /**
   * Construct Verifier from a certificate in PEM format
   * @param pem The certificate containing a public key
   */
  VerifierPtr make_verifier(const Pem& pem);

  ccf::crypto::Pem cert_der_to_pem(const std::vector<uint8_t>& der);
  std::vector<uint8_t> cert_pem_to_der(const Pem& pem);

  std::vector<uint8_t> public_key_der_from_cert(
    const std::vector<uint8_t>& der);

  ccf::crypto::Pem public_key_pem_from_cert(const std::vector<uint8_t>& der);

  std::string get_subject_name(const Pem& cert);
}
