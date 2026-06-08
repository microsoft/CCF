// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/key_pair.h"
#include "tls/ca.h"

#include <cstring>
#include <memory>
#include <openssl/x509.h>
#include <optional>

using namespace ccf::crypto::OpenSSL;

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
    bool auth_required;

    Unique_X509 own_cert;
    Unique_STACK_OF_X509 chain;
    std::shared_ptr<ccf::crypto::KeyPair_OpenSSL> own_pkey;
    bool has_own_cert = false;

  public:
    Cert(
      std::shared_ptr<CA> peer_ca_,
      const std::optional<ccf::crypto::Pem>& own_cert_ = std::nullopt,
      const std::optional<ccf::crypto::Pem>& own_pkey_ = std::nullopt,
      const std::optional<std::string>& peer_hostname_ = std::nullopt,
      bool auth_required_ = true) :
      peer_ca(peer_ca_),
      peer_hostname(peer_hostname_),
      auth_required(auth_required_)
    {
      if (own_cert_.has_value() && own_pkey_.has_value())
      {
        const auto certs =
          ccf::crypto::split_x509_cert_bundle(own_cert_->str());
        has_own_cert = true;

        {
          Unique_BIO certbio(certs[0]);
          own_cert = Unique_X509(certbio, true);
          own_pkey = std::make_shared<ccf::crypto::KeyPair_OpenSSL>(*own_pkey_);
        }

        if (certs.size() > 1)
        {
          for (auto it = certs.begin() + 1; it != certs.end(); ++it)
          {
            Unique_BIO certbio(*it);
            Unique_X509 cert(certbio, true);

            CHECK1(sk_X509_push(chain, cert));
            CHECK1(X509_up_ref(cert));
          }
        }
      }
    }

    ~Cert() = default;

    void use(SSL* ssl, SSL_CTX* ssl_ctx)
    {
      if (peer_hostname.has_value())
      {
        // Peer hostname for SNI
        SSL_set_tlsext_host_name(ssl, peer_hostname->c_str());
      }

      if (peer_ca)
      {
        peer_ca->use(ssl_ctx);
      }

      if (auth_required)
      {
        int opts = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        auto cb = [](int ok, x509_store_ctx_st*) {
          LOG_DEBUG_FMT("peer certificate verified: {}", ok);
          return ok;
        };
        SSL_CTX_set_verify(ssl_ctx, opts, cb);
        SSL_set_verify(ssl, opts, cb);
      }
      else
      {
        // Calling set_verify with SSL_VERIFY_PEER forces the handshake to
        // request a peer certificate. The server always sends it to the client
        // but not the other way around. Some code relies on the server doing
        // that, so we set this here. We return 1 from the validation callback
        // (a common pattern in OpenSSL implementations) because we don't want
        // to verify it here, just request it.
        auto cb = [](int, x509_store_ctx_st*) { return 1; };
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, cb);
        SSL_set_verify(ssl, SSL_VERIFY_PEER, cb);
      }

      if (has_own_cert)
      {
        CHECK1(
          SSL_CTX_use_cert_and_key(ssl_ctx, own_cert, *own_pkey, chain, 1));
        CHECK1(SSL_use_cert_and_key(ssl, own_cert, *own_pkey, chain, 1));
      }
    }
  };
}
