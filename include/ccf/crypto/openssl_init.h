// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf::crypto
{
  /** To be called once per thread, before calling the ccf::crypto::sha256
   *  functions (sha256.h) or calling internal CCF code making use of them.
   *
   *  Typical CCF application code does _NOT_ need to make these calls,
   *  they are exposed for unit tests that use ccfcrypto.a directly
   *  and skip typical initialization and shutdown.
   *
   *  These calls exist to create and cache an EVP_MD_CTX per thread and
   *  amortise creation costs that can be substantial fraction of the total
   *  hashing time for small messages.
   */
  void openssl_sha256_init();
  void openssl_sha256_shutdown();
}
