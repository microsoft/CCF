// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/mbedtls/entropy.h"
#include "crypto/mbedtls/mbedtls_wrappers.h"

#include <mbedtls/ctr_drbg.h>
#include <stddef.h>

using namespace crypto;

// This is just for libsss
extern "C" void randombytes(void* buf, size_t n)
{
  EntropyPtr entropy = create_entropy();
  entropy->random((unsigned char*)buf, n);
}
