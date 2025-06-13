// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// These macros setup return values for when the connection is reading/writing
// and needs more data or has an error.
//
// In OpenSSL, the return is -1/0/1 and the error code depends on what
// SSL_want() returns. So we need to return some distinct negative number
// and then handle WANT_READ/WANT_WRITE and errors.
//
// Depending on the error, the connection needs to close with success, failure
// or auth-failure.
#define TLS_READING -SSL_READING
#define TLS_WRITING -SSL_WRITING
#define TLS_ERR_WANT_READ -SSL_ERROR_WANT_READ
#define TLS_ERR_WANT_WRITE -SSL_ERROR_WANT_WRITE
#define TLS_ERR_CONN_CLOSE_NOTIFY -SSL_ERROR_ZERO_RETURN
#define TLS_ERR_NEED_CERT -SSL_ERROR_WANT_X509_LOOKUP
// Specific error to check validity of certificate, not emitted by OpenSSL, but
// by Context. We set to a bogus negative value that won't match any OpenSSL
// error code.
// Once we refactor the code to match the OpenSSL style we may not need this.
#define TLS_ERR_X509_VERIFY INT_MIN

#include "ccf/crypto/openssl/openssl_wrappers.h"

#include <string>

namespace tls
{
  inline std::string error_string(int ec)
  {
    return ccf::crypto::OpenSSL::error_string(ec);
  }
}
