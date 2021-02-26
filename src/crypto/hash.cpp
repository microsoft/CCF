// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "hash.h"

#include "mbedtls/hash.h"
#include "openssl/hash.h"

namespace crypto
{
  void default_sha256(const CBuffer& data, uint8_t* h)
  {
    return openssl_sha256(data, h);
  }
}