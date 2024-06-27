// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "tls/tls.h"

#include <doctest/doctest.h>
#include <openssl/ssl.h>

using namespace std;
using namespace ccf::crypto;

TEST_CASE("check QUIC OpenSSL library call")
{
  OpenSSL::Unique_SSL_CTX cfg(TLS_client_method());
  OpenSSL::Unique_SSL ssl(cfg);
  SSL_QUIC_METHOD* quic;
  SSL_set_quic_method(ssl, quic);
}