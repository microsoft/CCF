// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ca.h"
#include "ds/logger.h"
#include "tls/openssl/tls.h"

#include <cstring>
#include <memory>
#include <openssl/ssl.h>
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

    crypto::OpenSSL::Unique_X509 own_cert;
    crypto::OpenSSL::Unique_PKEY own_pkey;
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
      crypto::OpenSSL::Unique_X509 tmp_cert;
      crypto::OpenSSL::Unique_PKEY tmp_pkey;

      if (own_cert_.has_value() && own_pkey_.has_value())
      {
        BIO* certBio = BIO_new(BIO_s_mem());
        BIO_write(certBio, own_cert_->data(), own_cert_->size());
        X509* cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
        if (!cert)
        {
          auto err_str = tls::error_string(ERR_get_error());
          LOG_FAIL_FMT("Cert::ctor: Could not parse certificate: {}", err_str);
          throw std::logic_error("Could not parse certificate: " + err_str);
        }
        tmp_cert.reset(cert);

        BIO* pkBio = BIO_new(BIO_s_mem());
        BIO_write(pkBio, own_pkey_->data(), own_pkey_->size());
        EVP_PKEY* pk = PEM_read_bio_PrivateKey(pkBio, NULL, NULL, NULL);
        if (!pk)
        {
          auto err_str = tls::error_string(ERR_get_error());
          LOG_FAIL_FMT("Cert::ctor: Could not parse key: {}", err_str);
          throw std::logic_error("Could not parse key: " + err_str);
        }
        tmp_pkey.reset(pk);

        has_own_cert = true;
      }

      own_cert = std::move(tmp_cert);
      own_pkey = std::move(tmp_pkey);

      if (pw.n)
      {
        // FIXME: We don't seem to be using PW anywhere in CCF, so we should
        // really remove this option.
        LOG_FAIL_FMT("Cert::ctor: Unused password");
        throw std::logic_error(
          "Unused password: " + std::string((const char*)pw.p));
      }
    }

    ~Cert() {}

    void use(SSL* ssl, SSL_CTX* cfg)
    {
      if (peer_hostname.has_value())
      {
        LOG_TRACE_FMT(
          "Cert::use() : Hostname has value '{}'", peer_hostname->c_str());
        // Peer hostname is only checked against peer certificate (SAN
        // extension) if it is set. This lets us connect to peers that present
        // certificates with IPAddress in SAN field (mbedtls does not parse
        // IPAddress in SAN field). This is OK since we check for peer CA
        // endorsement.
        SSL_set1_host(ssl, peer_hostname->c_str());
      }

      if (peer_ca)
      {
        LOG_TRACE_FMT("Cert::use() : Peer CA use cfg");
        peer_ca->use(ssl, cfg);
      }

      // Calling set_verify with SSL_VERIFY_PEER forces the handshake to request
      // a peer certificate. The server always sends it to the client but not
      // the other way around. Some code relies on the server doing that, so we
      // set this here.
      // We return 1 from the validation callback (a common patter in OpenSSL
      // implementations) because we don't want to verify it here, just request
      // it.
      SSL_CTX_set_verify(
        cfg, SSL_VERIFY_PEER, [](int precheck, x509_store_ctx_st* st) {
          (void)precheck;
          (void)st;
          return 1;
        });
      SSL_set_verify(
        ssl, SSL_VERIFY_PEER, [](int precheck, x509_store_ctx_st* st) {
          (void)precheck;
          (void)st;
          return 1;
        });
      // FIXME: The MBedTLS implementation adds some verification, but any
      // further flags in OpenSSL's set_verify fail when MBedTLS doesn't.
      // We still need to request the peer cert every time, even if it's empty,
      // but it would be good to have some more strict checks on the actual
      // certificate at this level without leaving it for later.

      if (has_own_cert)
      {
        LOG_TRACE_FMT("Cert::use() : Has own cert & PK");
        // Chain of X509 certificates is 'nullptr', as we haven't established a
        // chain yet. Overrides = 0, only sets cert&key once, since they don't
        // change with repeated calls to use().
        int rc = SSL_CTX_use_cert_and_key(cfg, own_cert, own_pkey, nullptr, 1);
        if (!rc)
        {
          auto err_str = tls::error_string(ERR_get_error());
          LOG_FAIL_FMT("Cert::ctor: Invalid CTX certificate or key: ", err_str);
          throw std::logic_error("Invalid CTX certificate or key: " + err_str);
        }
        rc = SSL_use_cert_and_key(ssl, own_cert, own_pkey, nullptr, 1);
        if (!rc)
        {
          auto err_str = tls::error_string(ERR_get_error());
          LOG_FAIL_FMT("Cert::ctor: Invalid SSL certificate or key: ", err_str);
          throw std::logic_error("Invalid SSL certificate or key: " + err_str);
        }
      }
    }

    const X509* raw()
    {
      return own_cert;
    }
  };
}
