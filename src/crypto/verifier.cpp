// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "verifier.h"

#include "key_pair_mbedtls.h"
#include "key_pair_openssl.h"
#include "rsa_key_pair_mbedtls.h"
#include "rsa_key_pair_openssl.h"

#include <mbedtls/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace crypto
{
  static constexpr size_t max_pem_cert_size = 4096;

  // As these are not exposed by mbedTLS, define them here to allow simple
  // conversion from DER to PEM format
  static constexpr auto PEM_CERTIFICATE_HEADER =
    "-----BEGIN CERTIFICATE-----\n";
  static constexpr auto PEM_CERTIFICATE_FOOTER = "-----END CERTIFICATE-----\n";

  MDType Verifier_mbedTLS::get_md_type(mbedtls_md_type_t mdt) const
  {
    switch (mdt)
    {
      case MBEDTLS_MD_NONE:
        return MDType::NONE;
      case MBEDTLS_MD_SHA1:
        return MDType::SHA1;
      case MBEDTLS_MD_SHA256:
        return MDType::SHA256;
      case MBEDTLS_MD_SHA384:
        return MDType::SHA384;
      case MBEDTLS_MD_SHA512:
        return MDType::SHA512;
      default:
        return MDType::NONE;
    }
    return MDType::NONE;
  }

  Verifier_mbedTLS::Verifier_mbedTLS(const std::vector<uint8_t>& c) : Verifier()
  {
    cert = mbedtls::make_unique<mbedtls::X509Crt>();
    int rc = mbedtls_x509_crt_parse(cert.get(), c.data(), c.size());
    if (rc)
    {
      throw std::invalid_argument(fmt::format(
        "Failed to parse certificate: {}",
        PublicKey_mbedTLS::error_string(rc)));
    }

    md_type = get_md_type(cert->sig_md);

    // public_key expects to have unique ownership of the context and so does
    // `cert`, so we duplicate the key context here.
    unsigned char buf[2048];
    rc = mbedtls_pk_write_pubkey_pem(&cert->pk, buf, sizeof(buf));
    if (rc != 0)
    {
      throw std::runtime_error(fmt::format(
        "PEM export failed: {}", PublicKey_mbedTLS::error_string(rc)));
    }

    Pem pem(buf, sizeof(buf));

    if (mbedtls_pk_can_do(&cert->pk, MBEDTLS_PK_ECKEY))
    {
      public_key = std::make_unique<PublicKey_mbedTLS>(pem);
    }
    else if (mbedtls_pk_can_do(&cert->pk, MBEDTLS_PK_RSA))
    {
      public_key = std::make_unique<RSAPublicKey_mbedTLS>(pem);
    }
    else
    {
      throw std::logic_error("unsupported public key type");
    }
  }

  std::vector<uint8_t> Verifier_mbedTLS::cert_der()
  {
    return {cert->raw.p, cert->raw.p + cert->raw.len};
  }

  Pem Verifier_mbedTLS::cert_pem()
  {
    unsigned char buf[max_pem_cert_size];
    size_t len;

    auto rc = mbedtls_pem_write_buffer(
      PEM_CERTIFICATE_HEADER,
      PEM_CERTIFICATE_FOOTER,
      cert->raw.p,
      cert->raw.len,
      buf,
      max_pem_cert_size,
      &len);

    if (rc != 0)
    {
      throw std::logic_error(
        "mbedtls_pem_write_buffer failed: " +
        PublicKey_mbedTLS::error_string(rc));
    }

    return Pem(buf, len);
  }

  MDType Verifier_OpenSSL::get_md_type(int mdt) const
  {
    switch (mdt)
    {
      case NID_undef:
        return MDType::NONE;
      case NID_sha1:
        return MDType::SHA1;
      case NID_sha256:
        return MDType::SHA256;
      case NID_sha384:
        return MDType::SHA384;
      case NID_sha512:
        return MDType::SHA512;
      default:
        return MDType::NONE;
    }
    return MDType::NONE;
  }

  Verifier_OpenSSL::Verifier_OpenSSL(const std::vector<uint8_t>& c) : Verifier()
  {
    Unique_BIO certbio(c.data(), c.size());
    if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
    {
      BIO_reset(certbio);
      if (!(cert = d2i_X509_bio(certbio, NULL)))
      {
        throw std::invalid_argument(fmt::format(
          "OpenSSL error: {}",
          RSAPublicKey_OpenSSL::error_string(ERR_get_error())));
      }
    }

    int mdnid, pknid, secbits;
    X509_get_signature_info(cert, &mdnid, &pknid, &secbits, 0);
    md_type = get_md_type(mdnid);

    EVP_PKEY* pk = X509_get_pubkey(cert);

    if (EVP_PKEY_get0_EC_KEY(pk))
    {
      public_key = std::make_unique<PublicKey_OpenSSL>(pk);
    }
    else if (EVP_PKEY_get0_RSA(pk))
    {
      public_key = std::make_unique<RSAPublicKey_OpenSSL>(pk);
    }
    else
    {
      throw std::logic_error("unsupported public key type");
    }
  }

  Verifier_OpenSSL::~Verifier_OpenSSL()
  {
    if (cert)
      X509_free(cert);
  }

  std::vector<uint8_t> Verifier_OpenSSL::cert_der()
  {
    Unique_BIO mem;
    OPENSSL_CHECK1(i2d_X509_bio(mem, cert));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    return {(uint8_t*)bptr->data, (uint8_t*)bptr->data + bptr->length};
  }

  Pem Verifier_OpenSSL::cert_pem()
  {
    Unique_BIO mem;
    OPENSSL_CHECK1(PEM_write_bio_X509(mem, cert));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  using VerifierPtr = std::shared_ptr<Verifier>;
  using VerifierUniquePtr = std::unique_ptr<Verifier>;

  /**
   * Construct Verifier from a certificate in DER or PEM format
   *
   * @param cert Sequence of bytes containing the certificate
   */
  VerifierUniquePtr make_unique_verifier(const std::vector<uint8_t>& cert)
  {
#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
    return std::make_unique<Verifier_mbedTLS>(cert);
#else
    return std::make_unique<Verifier_OpenSSL>(cert);
#endif
  }

  VerifierPtr make_verifier(const std::vector<uint8_t>& cert)
  {
#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
    return std::make_shared<Verifier_mbedTLS>(cert);
#else
    return std::make_shared<Verifier_OpenSSL>(cert);
#endif
  }

  VerifierUniquePtr make_unique_verifier(const Pem& pem)
  {
    return make_unique_verifier(pem.raw());
  }

  VerifierPtr make_verifier(const Pem& pem)
  {
    return make_verifier(pem.raw());
  }

  crypto::Pem cert_der_to_pem(const std::vector<uint8_t>& der)
  {
    return make_verifier(der)->cert_pem();
  }

  std::vector<uint8_t> cert_pem_to_der(const std::string& pem_string)
  {
    return make_verifier(Pem(pem_string).raw())->cert_der();
  }

  Pem public_key_pem_from_cert(const Pem& cert)
  {
    return make_unique_verifier(cert)->public_key_pem();
  }

  void check_is_cert(const CBuffer& der)
  {
    make_unique_verifier((std::vector<uint8_t>)der); // throws on error
  }
}
