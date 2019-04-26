// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ca.h"

#include <cstring>
#include <memory>

namespace tls
{
  enum Auth
  {
    auth_default,
    auth_none,
    auth_optional,
    auth_required
  };

  class Cert
  {
  private:
    std::string hostname;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    std::shared_ptr<CA> peer_ca;
    Auth auth;

    bool has_cert;

  public:
    Cert(
      std::string hostname_,
      std::shared_ptr<CA> peer_ca_,
      CBuffer cert_ = nullb,
      CBuffer pkey_ = nullb,
      CBuffer pw = nullb,
      Auth auth_ = auth_default) :
      hostname(hostname_),
      peer_ca(peer_ca_),
      auth(auth_),
      has_cert(false)
    {
      mbedtls_x509_crt_init(&cert);
      mbedtls_pk_init(&pkey);

      if ((cert_.n > 0) && (pkey_.n > 0))
      {
        Pem pemCert(cert_);
        if (mbedtls_x509_crt_parse(&cert, pemCert.p, pemCert.n) != 0)
          throw std::logic_error("Could not parse certificate");

        Pem pemPk(pkey_);
        if (mbedtls_pk_parse_key(&pkey, pemPk.p, pemPk.n, pw.p, pw.n) != 0)
          throw std::logic_error("Could not parse key");

        has_cert = true;
      }
    }

    ~Cert()
    {
      mbedtls_x509_crt_free(&cert);
      mbedtls_pk_free(&pkey);
    }

    const std::string& host()
    {
      return hostname;
    }

    void use(mbedtls_ssl_context* ssl, mbedtls_ssl_config* cfg)
    {
      if (hostname.size() > 0)
        mbedtls_ssl_set_hostname(ssl, hostname.c_str());

      if (peer_ca)
        peer_ca->use(cfg);

      if (auth != auth_default)
        mbedtls_ssl_conf_authmode(cfg, authmode(auth));

      if (has_cert)
        mbedtls_ssl_conf_own_cert(cfg, &cert, &pkey);
    }

    bool sni(mbedtls_ssl_context* ssl, const unsigned char* name, size_t len)
    {
      if (hostname.size() > 0)
      {
        if (hostname.size() != len)
          return false;

        if (std::memcmp(hostname.c_str(), name, len) != 0)
          return false;
      }

      if (peer_ca)
        peer_ca->sni(ssl);

      if (auth != auth_default)
        mbedtls_ssl_set_hs_authmode(ssl, authmode(auth));

      if (has_cert)
        mbedtls_ssl_set_hs_own_cert(ssl, &cert, &pkey);

      return true;
    }

    const mbedtls_x509_crt* raw()
    {
      return &cert;
    }

  private:
    int authmode(Auth auth)
    {
      switch (auth)
      {
        case auth_none:
          return MBEDTLS_SSL_VERIFY_NONE;

        case auth_optional:
          return MBEDTLS_SSL_VERIFY_OPTIONAL;

        case auth_required:
          return MBEDTLS_SSL_VERIFY_REQUIRED;

        default:
        {}
      }

      return MBEDTLS_SSL_VERIFY_REQUIRED;
    }
  };
}
