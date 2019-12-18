// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ca.h"
#include "error_string.h"

#include <cstring>
#include <memory>
#include <optional>

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
    std::optional<std::string> peer_hostname;
    mbedtls_x509_crt own_cert;
    mbedtls_pk_context own_pkey;
    std::shared_ptr<CA> peer_ca;
    Auth auth;

    bool has_cert;

  public:
    Cert(
      std::shared_ptr<CA> peer_ca_,
      CBuffer own_cert_ = nullb,
      const tls::Pem& own_pkey_ = {},
      CBuffer pw = nullb,
      Auth auth_ = auth_default,
      std::optional<std::string> peer_hostname_ = std::nullopt) :
      peer_ca(peer_ca_),
      auth(auth_),
      peer_hostname(peer_hostname_),
      has_cert(false)
    {
      mbedtls_x509_crt_init(&own_cert);
      mbedtls_pk_init(&own_pkey);

      if ((own_cert_.n > 0) && (own_pkey_.size() > 0))
      {
        Pem pem_cert(own_cert_);
        int rc =
          mbedtls_x509_crt_parse(&own_cert, pem_cert.data(), pem_cert.size());

        if (rc != 0)
        {
          throw std::logic_error(
            "Could not parse certificate: " + error_string(rc));
        }

        rc = mbedtls_pk_parse_key(
          &own_pkey, own_pkey_.data(), own_pkey_.size(), pw.p, pw.n);
        if (rc != 0)
        {
          throw std::logic_error("Could not parse key: " + error_string(rc));
        }

        has_cert = true;
      }
    }

    ~Cert()
    {
      mbedtls_x509_crt_free(&own_cert);
      mbedtls_pk_free(&own_pkey);
    }

    void use(mbedtls_ssl_context* ssl, mbedtls_ssl_config* cfg)
    {
      if (peer_hostname.has_value())
      {
        // Peer hostname is only checked against peer certificate (SAN
        // extension) if it is set. This lets us connect to peers that present
        // certificates with IPAddress in SAN field (mbedtls does not parse
        // IPAddress in SAN field). This is OK since we check for peer CA
        // endorsement.
        mbedtls_ssl_set_hostname(ssl, peer_hostname->c_str());
      }

      if (peer_ca)
      {
        peer_ca->use(cfg);
      }

      if (auth != auth_default)
      {
        mbedtls_ssl_conf_authmode(cfg, authmode(auth));
      }

      if (has_cert)
      {
        mbedtls_ssl_conf_own_cert(cfg, &own_cert, &own_pkey);
      }
    }

    const mbedtls_x509_crt* raw()
    {
      return &own_cert;
    }

  private:
    int authmode(Auth auth)
    {
      switch (auth)
      {
        case auth_none:
        {
          return MBEDTLS_SSL_VERIFY_NONE;
        }

        case auth_optional:
        {
          return MBEDTLS_SSL_VERIFY_OPTIONAL;
        }

        case auth_required:
        {
          return MBEDTLS_SSL_VERIFY_REQUIRED;
        }

        default:
        {}
      }

      return MBEDTLS_SSL_VERIFY_REQUIRED;
    }
  };
}
