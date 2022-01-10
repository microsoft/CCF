// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Macros provided to interface MbedTLS and OpenSSL on the same implementation.
#ifndef TLS_PROVIDER_IS_MBEDTLS
// These macros setup return values for when the connection is reading/writing
// and needs more data or has an error.
//
// In OpenSSL, the return is -1/0/1 and the error code depends on what
// SSL_want() returns. So we need to return some distinct negative number
// and then handle WANT_READ/WANT_WRITE and errors.
//
// Depending on the error, the connection needs to close with success, failure
// or auth-failure.
//
// Some MbedTLS errors are not matched by OpenSSL, so we set some ridiculous
// negative number that will never match. This allows us to place the macro as
// a switch-case and not duplicate cases but also never match.
#  define TLS_READING -SSL_READING
#  define TLS_WRITING -SSL_WRITING
#  define TLS_ERR_WANT_READ -SSL_ERROR_WANT_READ
#  define TLS_ERR_WANT_WRITE -SSL_ERROR_WANT_WRITE
#  define TLS_ERR_CONN_CLOSE_NOTIFY -SSL_ERROR_ZERO_RETURN
#  define TLS_ERR_NEED_CERT -SSL_ERROR_WANT_X509_LOOKUP
// No counterpart in OpenSSL
#  define TLS_ERR_CONN_RESET INT_MIN
#  define TLS_ERR_PEER_VERIFY INT_MIN + 1
#  define TLS_ERR_X509_VERIFY INT_MIN + 2

#  include <openssl/err.h>
#  include <string>

namespace tls
{
  /// Returns the error string from an error code
  /// this is a copy of crypto's to allow control via TLS_PROVIDER_IS_MBEDTLS
  inline std::string error_string(int ec)
  {
    return ERR_error_string((unsigned long)ec, nullptr);
  }
}
#endif
