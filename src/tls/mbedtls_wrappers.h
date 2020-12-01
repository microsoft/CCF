// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <mbedtls/x509_crt.h>
#include <memory>

namespace mbedtls
{
  template <typename T>
  T make_unique();

#define DEFINE_MBEDTLS_WRAPPER(NEW_TYPE, MBED_TYPE, MBED_FREE_FN) \
  struct NEW_TYPE##_DELETER \
  { \
    void operator()(MBED_TYPE* ptr) \
    { \
      MBED_FREE_FN(ptr); \
      delete ptr; \
    } \
  }; \
  using NEW_TYPE = std::unique_ptr<MBED_TYPE, NEW_TYPE##_DELETER>; \
  template <> \
  inline NEW_TYPE make_unique<NEW_TYPE>() \
  { \
    return NEW_TYPE(new MBED_TYPE); \
  }

  DEFINE_MBEDTLS_WRAPPER(MPI, mbedtls_mpi, mbedtls_mpi_free);
  DEFINE_MBEDTLS_WRAPPER(PKContext, mbedtls_pk_context, mbedtls_pk_free);
  DEFINE_MBEDTLS_WRAPPER(X509Crl, mbedtls_x509_crl, mbedtls_x509_crl_free);
  DEFINE_MBEDTLS_WRAPPER(X509Crt, mbedtls_x509_crt, mbedtls_x509_crt_free);
  DEFINE_MBEDTLS_WRAPPER(X509Csr, mbedtls_x509_csr, mbedtls_x509_csr_free);
  DEFINE_MBEDTLS_WRAPPER(X509WriteCrt, mbedtls_x509write_cert, mbedtls_x509write_crt_free);
  DEFINE_MBEDTLS_WRAPPER(X509WriteCsr, mbedtls_x509write_csr, mbedtls_x509write_csr_free);
  DEFINE_MBEDTLS_WRAPPER(SSLContext, mbedtls_ssl_context, mbedtls_ssl_free);
  DEFINE_MBEDTLS_WRAPPER(SSLConfig, mbedtls_ssl_config, mbedtls_ssl_config_free);

#undef DEFINE_MBEDTLS_WRAPPER
}