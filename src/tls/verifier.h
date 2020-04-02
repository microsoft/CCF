// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "curve.h"

namespace tls
{
  static constexpr size_t max_pem_cert_size = 4096;

  // As these are not exposed by mbedlts, define them here to allow simple
  // conversion from DER to PEM format
  static constexpr auto PEM_CERTIFICATE_HEADER =
    "-----BEGIN CERTIFICATE-----\n";
  static constexpr auto PEM_CERTIFICATE_FOOTER = "-----END CERTIFICATE-----\n";

  class Verifier
  {
  protected:
    mutable mbedtls_x509_crt cert;

  public:
    /**
     * Construct from a pre-parsed cert
     *
     * @param c Initialised and parsed x509 cert
     */
    Verifier(const mbedtls_x509_crt& c) : cert(c) {}

    Verifier(const Verifier&) = delete;

    /**
     * Verify that a signature was produced on a hash with the private key
     * associated with the public key contained in the certificate.
     *
     * @param hash First byte in hash sequence
     * @param hash_size Number of bytes in hash sequence
     * @param signature First byte in signature sequence
     * @param signature_size Number of bytes in signature sequence
     *
     * @return Whether the signature matches the hash and the key
     */
    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* signature,
      size_t signature_size) const
    {
      const auto md_type = get_md_for_ec(get_ec_from_context(cert.pk));

      int rc = mbedtls_pk_verify(
        &cert.pk, md_type, hash, hash_size, signature, signature_size);

      if (rc)
        LOG_DEBUG_FMT("Failed to verify signature: {}", error_string(rc));

      return rc == 0;
    }

    /**
     * Verify that a signature was produced on a hash with the private key
     * associated with the public key contained in the certificate.
     *
     * @param hash Hash produced from contents as a sequence of bytes
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the hash and the key
     */
    bool verify_hash(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature) const
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size());
    }

    bool verify_hash(
      const std::vector<uint8_t>& hash,
      const uint8_t* sig,
      size_t sig_size) const
    {
      return verify_hash(hash.data(), hash.size(), sig, sig_size);
    }

    /**
     * Verify that a signature was produced on contents with the private key
     * associated with the public key contained in the certificate.
     *
     * @param contents Sequence of bytes that was signed
     * @param signature Signature as a sequence of bytes
     * @param md_type Digest algorithm to use. Derived from the
     * public key if MBEDTLS_MD_NONE.
     *
     * @return Whether the signature matches the contents and the key
     */
    bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature,
      mbedtls_md_type_t md_type = {}) const
    {
      return verify(
        contents.data(),
        contents.size(),
        signature.data(),
        signature.size(),
        md_type);
    }

    bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      mbedtls_md_type_t md_type = {}) const
    {
      HashBytes hash;
      do_hash(cert.pk, contents, contents_size, hash, md_type);

      return verify_hash(hash, sig, sig_size);
    }

    const mbedtls_x509_crt* raw()
    {
      return &cert;
    }

    std::vector<uint8_t> der_cert_data()
    {
      const auto crt = raw();
      return {crt->raw.p, crt->raw.p + crt->raw.len};
    }

    Pem cert_pem()
    {
      unsigned char buf[max_pem_cert_size];
      size_t len;
      const auto crt = raw();

      auto rc = mbedtls_pem_write_buffer(
        PEM_CERTIFICATE_HEADER,
        PEM_CERTIFICATE_FOOTER,
        crt->raw.p,
        crt->raw.len,
        buf,
        max_pem_cert_size,
        &len);

      if (rc != 0)
      {
        throw std::logic_error(
          "mbedtls_pem_write_buffer failed: " + error_string(rc));
      }

      return Pem({buf, len});
    }

    virtual ~Verifier()
    {
      mbedtls_x509_crt_free(&cert);
    }
  };

  class Verifier_k1Bitcoin : public Verifier
  {
  protected:
    BCk1ContextPtr bc_ctx = make_bc_context(SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey bc_pub;

  public:
    template <typename... Ts>
    Verifier_k1Bitcoin(Ts... ts) : Verifier(std::forward<Ts>(ts)...)
    {
      parse_secp256k_bc(cert.pk, bc_ctx->p, &bc_pub);
    }

    bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* signature,
      size_t signature_size) const override
    {
      bool ok = verify_secp256k_bc(
        bc_ctx->p, signature, signature_size, hash, hash_size, &bc_pub);

      return ok;
    }
  };

  using VerifierPtr = std::shared_ptr<Verifier>;
  using VerifierUniquePtr = std::unique_ptr<Verifier>;
  /**
   * Construct Verifier from a certificate in PEM format
   *
   * @param public_pem Sequence of bytes containing the certificate in PEM
   * format
   */
  inline VerifierUniquePtr make_unique_verifier(
    const std::vector<uint8_t>& cert_pem,
    bool use_bitcoin_impl = prefer_bitcoin_secp256k1)
  {
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int rc = mbedtls_x509_crt_parse(&cert, cert_pem.data(), cert_pem.size());
    if (rc)
    {
      mbedtls_x509_crt_free(&cert);
      throw std::invalid_argument(
        fmt::format("Failed to parse certificate: {}", error_string(rc)));
    }

    const auto curve = get_ec_from_context(cert.pk);

    if (curve == MBEDTLS_ECP_DP_SECP256K1 && use_bitcoin_impl)
    {
      return std::make_unique<Verifier_k1Bitcoin>(cert);
    }
    else
    {
      return std::make_unique<Verifier>(cert);
    }
  }

  inline VerifierPtr make_verifier(
    const std::vector<uint8_t>& cert_pem,
    bool use_bitcoin_impl = prefer_bitcoin_secp256k1)
  {
    return make_unique_verifier(cert_pem, use_bitcoin_impl);
  }

  inline std::vector<uint8_t> cert_der_to_pem(
    const std::vector<uint8_t>& der_cert_raw)
  {
    auto caller_pem = make_verifier(der_cert_raw)->cert_pem();
    return {caller_pem.str().begin(), caller_pem.str().end()};
  }
}