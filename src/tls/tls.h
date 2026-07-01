// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Specific error to flag a certificate validation failure during the handshake.
// This is not emitted by OpenSSL itself (its handshake failures surface as
// SSL_ERROR_SSL), but is set by Context so the caller can distinguish an
// authentication failure from a generic error. We use a bogus negative value
// that won't match any OpenSSL SSL_ERROR_* code.
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
