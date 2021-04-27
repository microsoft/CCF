// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "verifier.h"

#include "public_key.h"
#include "rsa_key_pair.h"

#include <mbedtls/pem.h>
#include <mbedtls/x509_crt.h>

namespace crypto
{
  using namespace mbedtls;

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
      throw std::invalid_argument(
        fmt::format("Failed to parse certificate: {}", error_string(rc)));
    }

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
        "mbedtls_pem_write_buffer failed: " + error_string(rc));
    }

    return Pem(buf, len);
  }

  class CertificateChain
  {
  public:
    size_t n = 0;
    mbedtls_x509_crt* raw = NULL;

    CertificateChain(const std::vector<const Pem*>& certs)
    {
      if (!certs.empty())
      {
        n = certs.size();
        raw = new mbedtls_x509_crt[certs.size()];

        for (size_t i = 0; i < certs.size(); i++)
        {
          mbedtls_x509_crt_init(&raw[i]);
        }

        for (size_t i = 0; i < certs.size(); i++)
        {
          auto& tc = certs[i];
          int rc = mbedtls_x509_crt_parse(&raw[i], tc->data(), tc->size());
          if (rc != 0)
          {
            throw std::runtime_error(
              "Could not parse PEM certificate: " + error_string(rc));
          }
        }
      }
    }

    ~CertificateChain()
    {
      for (size_t i = 0; i < n; i++)
      {
        mbedtls_x509_crt_free(&raw[i]);
      }
      delete[] raw;
    }
  };

  bool Verifier_mbedTLS::verify_certificate(
    const std::vector<const Pem*>& trusted_certs)
  {
    CertificateChain chain(trusted_certs);

    uint32_t flags;
    int rc = mbedtls_x509_crt_verify(
      cert.get(), chain.raw, NULL, NULL, &flags, NULL, NULL);

    return rc == 0 && flags == 0;
  }

  bool Verifier_mbedTLS::is_self_signed() const
  {
    return (cert->issuer_raw.len == cert->subject_raw.len) &&
      memcmp(cert->issuer_raw.p, cert->subject_raw.p, cert->subject_raw.len) ==
      0;
  }

  std::string Verifier_mbedTLS::serial_number() const
  {
    char buf[64];
    int rc = mbedtls_x509_serial_gets(buf, sizeof(buf), &cert->serial);
    if (rc < 0)
    {
      throw std::runtime_error(
        "mbedtls_x509_serial_gets failed: " + error_string(rc));
    }
    return buf;
  }
}