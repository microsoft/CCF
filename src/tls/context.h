// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "cert.h"
#include "crypto/entropy.h"
#include "crypto/mbedtls/mbedtls_wrappers.h"
#include "error_string.h"

#include <memory>

using namespace crypto;

namespace tls
{
  class Context
  {
  protected:
    mbedtls::SSLContext ssl = nullptr;
    mbedtls::SSLConfig cfg = nullptr;
    crypto::EntropyPtr entropy;

#ifndef NO_STRICT_TLS_CIPHERSUITES
    const int ciphersuites[2] = {
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0};
#endif

  public:
    Context(bool client, bool dgram) : entropy(crypto::create_entropy())
    {
      int rc = 0;

      auto tmp_ssl = mbedtls::make_unique<mbedtls::SSLContext>();
      auto tmp_cfg = mbedtls::make_unique<mbedtls::SSLConfig>();

      mbedtls_ssl_conf_rng(
        tmp_cfg.get(), entropy->get_rng(), entropy->get_data());

      rc = mbedtls_ssl_config_defaults(
        tmp_cfg.get(),
        client ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
        dgram ? MBEDTLS_SSL_TRANSPORT_DATAGRAM : MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
      if (rc != 0)
      {
        throw std::logic_error(fmt::format(
          "mbedtls_ssl_config_defaults failed: {}", error_string(rc)));
      }
#ifndef NO_STRICT_TLS_CIPHERSUITES
      if (!client)
        mbedtls_ssl_conf_ciphersuites(tmp_cfg.get(), ciphersuites);
#endif

      // Require TLS 1.2
      mbedtls_ssl_conf_min_version(
        tmp_cfg.get(),
        MBEDTLS_SSL_MAJOR_VERSION_3,
        MBEDTLS_SSL_MINOR_VERSION_3);

      rc = mbedtls_ssl_setup(tmp_ssl.get(), tmp_cfg.get());
      if (rc != 0)
      {
        throw std::logic_error(
          fmt::format("mbedtls_ssl_setup failed: {}", error_string(rc)));
      }

      ssl = std::move(tmp_ssl);
      cfg = std::move(tmp_cfg);
    }

    virtual ~Context() {}

    void set_bio(
      void* enclave,
      mbedtls_ssl_send_t send,
      mbedtls_ssl_recv_t recv,
      void (*dbg)(void*, int, const char*, int, const char*))
    {
      mbedtls_ssl_conf_dbg(cfg.get(), dbg, enclave);
      mbedtls_ssl_set_bio(ssl.get(), enclave, send, recv, nullptr);
    }

    int handshake()
    {
      return mbedtls_ssl_handshake(ssl.get());
    }

    size_t available_bytes()
    {
      return mbedtls_ssl_get_bytes_avail(ssl.get());
    }

    int read(uint8_t* buf, size_t len)
    {
      return mbedtls_ssl_read(ssl.get(), buf, len);
    }

    int write(const uint8_t* buf, size_t len)
    {
      return mbedtls_ssl_write(ssl.get(), buf, len);
    }

    int close()
    {
      return mbedtls_ssl_close_notify(ssl.get());
    }

    int verify_result()
    {
      return mbedtls_ssl_get_verify_result(ssl.get());
    }

    virtual std::string host()
    {
      return {};
    }

    const mbedtls_x509_crt* peer_cert()
    {
      return mbedtls_ssl_get_peer_cert(ssl.get());
    }

    void set_require_auth(bool state)
    {
      mbedtls_ssl_conf_authmode(
        cfg.get(),
        state ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
  };
}
