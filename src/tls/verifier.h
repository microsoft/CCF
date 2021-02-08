// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "curve.h"
#include "error_string.h"
#include "hash.h"
#include "key_pair.h"
#include "pem.h"
#include "rsa_key_pair.h"

#include <mbedtls/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace tls
{
  static constexpr size_t max_pem_cert_size = 4096;

  // As these are not exposed by mbedTLS, define them here to allow simple
  // conversion from DER to PEM format
  static constexpr auto PEM_CERTIFICATE_HEADER =
    "-----BEGIN CERTIFICATE-----\n";
  static constexpr auto PEM_CERTIFICATE_FOOTER = "-----END CERTIFICATE-----\n";

  class VerifierBase
  {
  protected:
    std::shared_ptr<PublicKeyBase> public_key;
    MDType md_type = MDType::NONE;

  public:
    VerifierBase() : public_key(nullptr) {}
    virtual ~VerifierBase() {}

    virtual std::vector<uint8_t> cert_der() = 0;
    virtual Pem cert_pem() = 0;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type) const
    {
      if (md_type == MDType::NONE)
        md_type = this->md_type;

      return public_key->verify(
        contents, contents_size, sig, sig_size, md_type);
    }

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type,
      HashBytes& hash_bytes) const
    {
      if (md_type == MDType::NONE)
        md_type = this->md_type;

      return public_key->verify(
        contents, contents_size, sig, sig_size, md_type, hash_bytes);
    }

    virtual bool verify(
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

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature,
      MDType md_type,
      HashBytes& hash_bytes) const
    {
      return verify(
        contents.data(),
        contents.size(),
        signature.data(),
        signature.size(),
        md_type,
        hash_bytes);
    }

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* sig,
      size_t sig_size,
      MDType md_type = MDType::NONE)
    {
      if (md_type == MDType::NONE)
        md_type = this->md_type;

      return public_key->verify_hash(hash, hash_size, sig, sig_size, md_type);
    }

    virtual bool verify_hash(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature,
      MDType md_type = MDType::NONE)
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size(), md_type);
    }

    template <size_t SIZE>
    bool verify_hash(
      const std::array<uint8_t, SIZE>& hash,
      const std::vector<uint8_t>& signature,
      MDType md_type = MDType::NONE)
    {
      return verify_hash(
        hash.data(), hash.size(), signature.data(), signature.size(), md_type);
    }

    virtual CurveID get_curve_id() const
    {
      return public_key->get_curve_id();
    }
  };

  class Verifier_MBedTLS : public VerifierBase
  {
  protected:
    mutable mbedtls::X509Crt cert;

    inline MDType get_md_type(mbedtls_md_type_t mdt) const
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

  public:
    /**
     * Construct from a certificate
     *
     * @param c Certificate in DER or PEM format
     */
    Verifier_MBedTLS(const std::vector<uint8_t>& c) : VerifierBase()
    {
      cert = mbedtls::make_unique<mbedtls::X509Crt>();
      int rc = mbedtls_x509_crt_parse(cert.get(), c.data(), c.size());
      if (rc)
      {
        throw std::invalid_argument(
          fmt::format("Failed to parse certificate: {}", error_string(rc)));
      }

      md_type = get_md_type(cert->sig_md);

      // public_key expects to have unique ownership of the context and so does
      // `cert`, so we duplicate the key context here.
      unsigned char buf[2048];
      rc = mbedtls_pk_write_pubkey_pem(&cert->pk, buf, sizeof(buf));
      if (rc != 0)
      {
        throw std::runtime_error(
          fmt::format("PEM export failed: {}", error_string(rc)));
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

    Verifier_MBedTLS(const Verifier_MBedTLS&) = delete;

    virtual ~Verifier_MBedTLS() = default;

    const mbedtls_x509_crt* raw()
    {
      return cert.get();
    }

    virtual std::vector<uint8_t> cert_der() override
    {
      return {cert->raw.p, cert->raw.p + cert->raw.len};
    }

    virtual Pem cert_pem() override
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
          "mbedtls_pem_write_buffer failed: " + error_string(rc));
      }

      return Pem(buf, len);
    }
  };

  class Verifier_OpenSSL : public VerifierBase
  {
  protected:
    mutable X509* cert;

    MDType get_md_type(int mdt) const
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

  public:
    /**
     * Construct from a certificate
     *
     * @param c Certificate in DER or PEM format
     */
    Verifier_OpenSSL(const std::vector<uint8_t>& c) : VerifierBase()
    {
      BIO* certbio = BIO_new_mem_buf(c.data(), c.size());
      if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
      {
        throw std::invalid_argument(fmt::format(
          "OpenSSL error: {}", ERR_error_string(ERR_get_error(), NULL)));
      }
      BIO_free(certbio);

      int mdnid, pknid, secbits;
      X509_get_signature_info(cert, &mdnid, &pknid, &secbits, 0);
      md_type = get_md_type(mdnid);

      EVP_PKEY* pk = X509_get_pubkey(cert);

      BIO* buf = BIO_new(BIO_s_mem());
      if (!buf)
        throw std::runtime_error("out of memory");

      OPENSSL_CHECK1(PEM_write_bio_PUBKEY(buf, pk));

      BUF_MEM* bptr;
      BIO_get_mem_ptr(buf, &bptr);
      Pem pk_pem((uint8_t*)bptr->data, bptr->length);
      BIO_free(buf);

      if (EVP_PKEY_get0_EC_KEY(pk))
      {
        public_key = std::make_unique<PublicKey_OpenSSL>(pk_pem);
      }
      // else if (mbedtls_pk_can_do(&cert->pk, MBEDTLS_PK_RSA))
      // {
      //   public_key = std::make_unique<RSAPublicKey_mbedTLS>(buf);
      // }
      else
      {
        throw std::logic_error("unsupported public key type");
      }

      EVP_PKEY_free(pk);
    }

    Verifier_OpenSSL(Verifier_OpenSSL&& v) = default;

    Verifier_OpenSSL(const Verifier_OpenSSL&) = delete;

    virtual ~Verifier_OpenSSL()
    {
      if (cert)
        X509_free(cert);
    }

    const X509* raw()
    {
      return cert;
    }

    virtual std::vector<uint8_t> cert_der() override
    {
      BIO* mem = BIO_new(BIO_s_mem());
      OPENSSL_CHECK1(i2d_X509_bio(mem, cert));

      BUF_MEM* bptr;
      BIO_get_mem_ptr(mem, &bptr);
      std::vector<uint8_t> result = {(uint8_t*)bptr->data,
                                     (uint8_t*)bptr->data + bptr->length};
      BIO_free(mem);
      return result;
    }

    virtual Pem cert_pem() override
    {
      BIO* mem = BIO_new(BIO_s_mem());
      OPENSSL_CHECK1(i2d_X509_bio(mem, cert));

      BUF_MEM* bptr;
      BIO_get_mem_ptr(mem, &bptr);
      Pem result((uint8_t*)bptr->data, bptr->length);
      BIO_free(mem);

      return result;
    }
  };

  using VerifierPtr = std::shared_ptr<VerifierBase>;
  using VerifierUniquePtr = std::unique_ptr<VerifierBase>;

  /**
   * Construct Verifier from a certificate in DER or PEM format
   *
   * @param cert Sequence of bytes containing the certificate
   */
  inline VerifierUniquePtr make_unique_verifier(
    const std::vector<uint8_t>& cert)
  {
    return std::make_unique<Verifier_MBedTLS>(cert);
  }

  inline VerifierPtr make_verifier(const Pem& cert)
  {
    return make_unique_verifier(cert.raw());
  }

  inline tls::Pem cert_der_to_pem(const std::vector<uint8_t>& der_cert_raw)
  {
    return make_verifier(der_cert_raw)->cert_pem();
  }

  inline std::vector<uint8_t> cert_pem_to_der(const std::string& pem_cert_raw)
  {
    return make_verifier(pem_cert_raw)->cert_der();
  }
}