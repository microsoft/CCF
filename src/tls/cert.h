// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ca.h"
#include "crypto/mbedtls/mbedtls_wrappers.h"
#include "error_string.h"

#include <cstring>
#include <memory>
#include <optional>

using namespace crypto;

namespace tls
{
  enum Auth
  {
    auth_default,
    auth_none,
    auth_optional,
    auth_required
  };

  // This class represents the authentication/authorization context for a TLS
  // session. At least, it contains the peer's CA. At most, it also contains our
  // own private key/certificate which will be presented in the TLS handshake.
  // The peer's certificate verification can be overridden with the auth
  // parameter.
  class Cert
  {
  private:
    std::shared_ptr<CA> peer_ca;
    std::optional<std::string> peer_hostname;

    mbedtls::X509Crt own_cert = nullptr;
    mbedtls::PKContext own_pkey = nullptr;
    bool has_own_cert;

    Auth auth;

  public:
    Cert(
      std::shared_ptr<CA> peer_ca_,
      const std::optional<crypto::Pem>& own_cert_ = std::nullopt,
      const std::optional<crypto::Pem>& own_pkey_ = std::nullopt,
      CBuffer pw = nullb,
      Auth auth_ = auth_default,
      const std::optional<std::string>& peer_hostname_ = std::nullopt) :
      peer_ca(peer_ca_),
      peer_hostname(peer_hostname_),
      has_own_cert(false),
      auth(auth_)
    {
      auto tmp_cert = mbedtls::make_unique<mbedtls::X509Crt>();
      auto tmp_pkey = mbedtls::make_unique<mbedtls::PKContext>();

      if (own_cert_.has_value() && own_pkey_.has_value())
      {
        int rc = mbedtls_x509_crt_parse(
          tmp_cert.get(), own_cert_->data(), own_cert_->size());

        if (rc != 0)
        {
          throw std::logic_error(
            "Could not parse certificate: " + error_string(rc));
        }

        rc = mbedtls_pk_parse_key(
          tmp_pkey.get(), own_pkey_->data(), own_pkey_->size(), pw.p, pw.n);
        if (rc != 0)
        {
          throw std::logic_error("Could not parse key: " + error_string(rc));
        }

        has_own_cert = true;
      }

      own_cert = std::move(tmp_cert);
      own_pkey = std::move(tmp_pkey);
    }

    ~Cert() {}

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

      if (has_own_cert)
      {
        mbedtls_ssl_conf_own_cert(cfg, own_cert.get(), own_pkey.get());
      }
    }

    const mbedtls_x509_crt* raw()
    {
      return own_cert.get();
    }

  private:
    int authmode(Auth auth)
    {
      switch (auth)
      {
        case auth_none:
        {
          // Peer certificate is not checked
          return MBEDTLS_SSL_VERIFY_NONE;
        }

        case auth_optional:
        {
          // Peer certificate is checked but handshake continues even if
          // verification fails
          return MBEDTLS_SSL_VERIFY_OPTIONAL;
        }

        case auth_required:
        {
          // Peer must present a valid certificate
          return MBEDTLS_SSL_VERIFY_REQUIRED;
        }

        default:
        {
        }
      }

      return MBEDTLS_SSL_VERIFY_REQUIRED;
    }
  };
}
