// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <mbedtls/x509_crt.h>
#include <memory>

namespace mbedtls
{
#define DEFINE_MBEDTLS_WRAPPER(NEW_TYPE, MBED_TYPE, MBED_FREE_FN) \
  struct NEW_TYPE \
  { \
    MBED_TYPE raw; \
    ~NEW_TYPE() \
    { \
      MBED_FREE_FN(&raw); \
    } \
    MBED_TYPE* get() \
    { \
      return &raw; \
    } \
  };

  DEFINE_MBEDTLS_WRAPPER(X509Crt, mbedtls_x509_crt, mbedtls_x509_crt_free);

#undef DEFINE_MBEDTLS_WRAPPER
}