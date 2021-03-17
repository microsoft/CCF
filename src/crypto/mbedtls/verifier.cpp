// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "verifier.h"

#include "public_key.h"
#include "rsa_key_pair.h"

#include <mbedtls/pem.h>

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

  bool Verifier_mbedTLS::validate_certificate(const Pem& ca_pem)
  {
    return true;
  }
}