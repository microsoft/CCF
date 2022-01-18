// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/openssl/key_pair.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "tls/ca.h"

#include <cstring>
#include <memory>
#include <openssl/x509.h>
#include <optional>

using namespace crypto;
using namespace crypto::OpenSSL;

namespace tls
{
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
    Auth auth;

    Unique_X509 own_cert;
    std::shared_ptr<KeyPair_OpenSSL> own_pkey;
    bool has_own_cert = false;

  public:
    Cert(
      std::shared_ptr<CA> peer_ca_,
      const std::optional<crypto::Pem>& own_cert_ = std::nullopt,
      const std::optional<crypto::Pem>& own_pkey_ = std::nullopt,
      Auth auth_ = auth_default,
      const std::optional<std::string>& peer_hostname_ = std::nullopt) :
      peer_ca(peer_ca_),
      peer_hostname(peer_hostname_),
      auth(auth_)
    {
      if (own_cert_.has_value() && own_pkey_.has_value())
      {
        Unique_BIO certbio(*own_cert_);
        own_cert = Unique_X509(certbio, true);
        own_pkey = std::make_shared<KeyPair_OpenSSL>(*own_pkey_);
        has_own_cert = true;
      }
    }

    ~Cert() = default;

    void use(SSL* ssl, SSL_CTX* ssl_ctx)
    {
      if (peer_hostname.has_value())
      {
        // Peer hostname is only checked against peer certificate (SAN
        // extension) if it is set. This lets us connect to peers that present
        // certificates with IPAddress in SAN field (mbedtls does not parse
        // IPAddress in SAN field). This is OK since we check for peer CA
        // endorsement.
        SSL_set1_host(ssl, peer_hostname->c_str());
      }

      if (peer_ca)
      {
        peer_ca->use(ssl_ctx);
      }

      if (auth != auth_default)
      {
        SSL_CTX_set_verify(ssl_ctx, authmode(auth), NULL);
      }

      if (has_own_cert)
      {
        CHECK1(SSL_CTX_use_cert_and_key(ssl_ctx, own_cert, *own_pkey, NULL, 1));
        CHECK1(SSL_use_cert_and_key(ssl, own_cert, *own_pkey, NULL, 1));
      }
    }

  private:
    int authmode(Auth auth)
    {
      switch (auth)
      {
        case auth_none:
        {
          // Peer certificate is not checked
          return SSL_VERIFY_NONE;
        }

        case auth_required:
        default:
        {
          return SSL_VERIFY_PEER;
        }
      }
    }
  };
}
