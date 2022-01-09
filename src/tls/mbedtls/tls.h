// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/oid.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

// Macros provided to interface MbedTLS and OpenSSL on the same implementation.
#ifdef TLS_PROVIDER_IS_MBEDTLS
// These macros setup return values for when the connection is reading/writing
// and needs more data. In MbedTLS, the return value is straight WANT_READ and
// WANT_WRITE, which are negative and the API knows how to handle it.
#  define TLS_READING MBEDTLS_ERR_SSL_WANT_READ
#  define TLS_WRITING MBEDTLS_ERR_SSL_WANT_WRITE
// These macros are errors from read/write, including during handshake.
// Depending on the error, the connection needs to close with success, failure
// or auth-failure.
#  define TLS_ERR_WANT_READ MBEDTLS_ERR_SSL_WANT_READ
#  define TLS_ERR_WANT_WRITE MBEDTLS_ERR_SSL_WANT_WRITE
#  define TLS_ERR_CONN_RESET MBEDTLS_ERR_NET_CONN_RESET
#  define TLS_ERR_CONN_CLOSE_NOTIFY MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
#  define TLS_ERR_NEED_CERT MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE
#  define TLS_ERR_PEER_VERIFY MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED
#  define TLS_ERR_X509_VERIFY MBEDTLS_ERR_X509_CERT_VERIFY_FAILED

namespace tls
{
  /// Returns the error string from an error code
  /// this is a copy of crypto's to all control via TLS_PROVIDER_IS_MBEDTLS
  inline std::string error_string(int err)
  {
    constexpr size_t len = 256;
    char buf[len];
    mbedtls_strerror(err, buf, len);

    if (strlen(buf) == 0)
    {
      return std::to_string(err);
    }

    return std::string(buf);
  }
}
#endif
