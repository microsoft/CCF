// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <memory>

namespace mbedtls
{
  template <typename T>
  T make_unique();

#define DEFINE_MBEDTLS_WRAPPER( \
  NEW_TYPE, MBED_TYPE, MBED_INIT_FN, MBED_FREE_FN) \
  struct NEW_TYPE##Deleter \
  { \
    void operator()(MBED_TYPE* ptr) \
    { \
      MBED_FREE_FN(ptr); \
      delete ptr; \
    } \
  }; \
  using NEW_TYPE = std::unique_ptr<MBED_TYPE, NEW_TYPE##Deleter>; \
  template <> \
  inline NEW_TYPE make_unique<NEW_TYPE>() \
  { \
    auto p = new MBED_TYPE; \
    MBED_INIT_FN(p); \
    return NEW_TYPE(p); \
  }

  DEFINE_MBEDTLS_WRAPPER(
    CtrDrbg,
    mbedtls_ctr_drbg_context,
    mbedtls_ctr_drbg_init,
    mbedtls_ctr_drbg_free);
  DEFINE_MBEDTLS_WRAPPER(
    ECDHContext, mbedtls_ecdh_context, mbedtls_ecdh_init, mbedtls_ecdh_free);
  DEFINE_MBEDTLS_WRAPPER(
    Entropy,
    mbedtls_entropy_context,
    mbedtls_entropy_init,
    mbedtls_entropy_free);
  DEFINE_MBEDTLS_WRAPPER(
    GcmContext, mbedtls_gcm_context, mbedtls_gcm_init, mbedtls_gcm_free);
  DEFINE_MBEDTLS_WRAPPER(MPI, mbedtls_mpi, mbedtls_mpi_init, mbedtls_mpi_free);
  DEFINE_MBEDTLS_WRAPPER(
    NetContext, mbedtls_net_context, mbedtls_net_init, mbedtls_net_free);
  DEFINE_MBEDTLS_WRAPPER(
    PKContext, mbedtls_pk_context, mbedtls_pk_init, mbedtls_pk_free);
  DEFINE_MBEDTLS_WRAPPER(
    SSLConfig,
    mbedtls_ssl_config,
    mbedtls_ssl_config_init,
    mbedtls_ssl_config_free);
  DEFINE_MBEDTLS_WRAPPER(
    SSLContext, mbedtls_ssl_context, mbedtls_ssl_init, mbedtls_ssl_free);
  DEFINE_MBEDTLS_WRAPPER(
    X509Crl, mbedtls_x509_crl, mbedtls_x509_crl_init, mbedtls_x509_crl_free);
  DEFINE_MBEDTLS_WRAPPER(
    X509Crt, mbedtls_x509_crt, mbedtls_x509_crt_init, mbedtls_x509_crt_free);
  DEFINE_MBEDTLS_WRAPPER(
    X509Csr, mbedtls_x509_csr, mbedtls_x509_csr_init, mbedtls_x509_csr_free);
  DEFINE_MBEDTLS_WRAPPER(
    X509WriteCrt,
    mbedtls_x509write_cert,
    mbedtls_x509write_crt_init,
    mbedtls_x509write_crt_free);
  DEFINE_MBEDTLS_WRAPPER(
    X509WriteCsr,
    mbedtls_x509write_csr,
    mbedtls_x509write_csr_init,
    mbedtls_x509write_csr_free);
  DEFINE_MBEDTLS_WRAPPER(
    SHA256Ctx,
    mbedtls_sha256_context,
    mbedtls_sha256_init,
    mbedtls_sha256_free);

#undef DEFINE_MBEDTLS_WRAPPER
}