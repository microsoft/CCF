// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "cert.h"
#include "entropy.h"

#include <memory>

namespace tls
{
  class Context
  {
  protected:
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config cfg;
    EntropyPtr entropy;

#ifndef NO_STRICT_TLS_CIPHERSUITES
#  ifdef MOD_MBEDTLS
    const int ciphersuites[3] = {
      MBEDTLS_TLS_ECDHE_EDDSA_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      0};
#  else
    const int ciphersuites[2] = {
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0};
#  endif
#endif

  public:
    Context(bool client, bool dgram) : entropy(tls::create_entropy())
    {
      mbedtls_ssl_init(&ssl);
      mbedtls_ssl_config_init(&cfg);
      mbedtls_ssl_conf_rng(&cfg, entropy->get_rng(), entropy->get_data());

      if (
        mbedtls_ssl_config_defaults(
          &cfg,
          client ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
          dgram ? MBEDTLS_SSL_TRANSPORT_DATAGRAM : MBEDTLS_SSL_TRANSPORT_STREAM,
          MBEDTLS_SSL_PRESET_DEFAULT) != 0)
      {
        throw std::logic_error("Could not set SSL config defaults");
      }
#ifndef NO_STRICT_TLS_CIPHERSUITES
      if (!client)
        mbedtls_ssl_conf_ciphersuites(&cfg, ciphersuites);
#endif

      // Require TLS 1.2
      mbedtls_ssl_conf_min_version(
        &cfg, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

      if (mbedtls_ssl_setup(&ssl, &cfg) != 0)
        throw std::logic_error("Could not set up SSL");
    }

    virtual ~Context()
    {
      mbedtls_ssl_free(&ssl);
      mbedtls_ssl_config_free(&cfg);
    }

    void set_bio(
      void* enclave,
      mbedtls_ssl_send_t send,
      mbedtls_ssl_recv_t recv,
      void (*dbg)(void*, int, const char*, int, const char*))
    {
      mbedtls_ssl_conf_dbg(&cfg, dbg, enclave);
      mbedtls_ssl_set_bio(&ssl, enclave, send, recv, NULL);
    }

    int handshake()
    {
      return mbedtls_ssl_handshake(&ssl);
    }

    size_t available_bytes()
    {
      return mbedtls_ssl_get_bytes_avail(&ssl);
    }

    int read(uint8_t* buf, size_t len)
    {
      return mbedtls_ssl_read(&ssl, buf, len);
    }

    int write(const uint8_t* buf, size_t len)
    {
      return mbedtls_ssl_write(&ssl, buf, len);
    }

    int close()
    {
      return mbedtls_ssl_close_notify(&ssl);
    }

    int verify_result()
    {
      return mbedtls_ssl_get_verify_result(&ssl);
    }

    virtual std::string host()
    {
      return {};
    }

    const mbedtls_x509_crt* peer_cert()
    {
      return mbedtls_ssl_get_peer_cert(&ssl);
    }

    void set_require_auth(bool state)
    {
      mbedtls_ssl_conf_authmode(
        &cfg,
        state ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
  };
}
