// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string.h>
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#else
#  include <openenclave/host_verify.h>
#endif
#include <openenclave/attestation/verifier.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/bits/sgx/sgxtypes.h>

static const char* oid_maa_sgx_quote_with_collateral = "1.2.840.113556.10.1.1";

// UUID for SGX quotes without header.
static const oe_uuid_t _sgx_quote_uuid = {
    OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA};

#define KEY_BUFF_SIZE 2048

// Internal OE types and functions
extern "C" {

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

typedef struct _oe_cert
{
    /* Internal private implementation */
    uint64_t impl[4];
} oe_cert_t;

typedef struct _oe_cert_chain
{
    /* Internal private implementation */
    uint64_t impl[4];
} oe_cert_chain_t;

typedef struct _oe_crl
{
    /* Internal private implementation */
    uint64_t impl[4];
} oe_crl_t;

typedef struct _oe_sha256_context
{
    /* Internal private implementation */
    uint64_t impl[16];
} oe_sha256_context_t;

#define OE_SHA256_SIZE 32

typedef struct _OE_SHA256
{
    unsigned char buf[OE_SHA256_SIZE];
} OE_SHA256;

oe_result_t oe_memset_s(
    void* dst,
    size_t dst_size,
    int value,
    size_t num_bytes);

oe_result_t oe_cert_free(oe_cert_t* cert);

oe_result_t oe_cert_read_der(
    oe_cert_t* cert,
    const void* der_data,
    size_t der_size);

oe_result_t oe_cert_find_extension(
    const oe_cert_t* cert,
    const char* oid,
    uint8_t* data,
    size_t* size);

oe_result_t oe_cert_verify(
    oe_cert_t* cert,
    oe_cert_chain_t* chain,
    const oe_crl_t* const* crls,
    size_t num_crls);

oe_result_t oe_cert_write_public_key_pem(
    const oe_cert_t* cert,
    uint8_t* pem_data,
    size_t* pem_size);

oe_result_t oe_sha256_init(oe_sha256_context_t* context);

oe_result_t oe_sha256_update(
    oe_sha256_context_t* context,
    const void* data,
    size_t size);

oe_result_t oe_sha256_final(oe_sha256_context_t* context, OE_SHA256* sha256);

// Logging and error check macros to avoid changing copied OE code.
typedef enum _oe_log_level
{
    OE_LOG_LEVEL_NONE = 0,
    OE_LOG_LEVEL_FATAL,
    OE_LOG_LEVEL_ERROR,
    OE_LOG_LEVEL_WARNING,
    OE_LOG_LEVEL_INFO,
    OE_LOG_LEVEL_VERBOSE,
    OE_LOG_LEVEL_MAX
} oe_log_level_t;

oe_result_t oe_log(oe_log_level_t level, const char* fmt, ...);

#define OE_TRACE(level, ...)        \
    do                              \
    {                               \
        oe_log(level, __VA_ARGS__); \
    } while (0)

#define OE_TRACE_FATAL(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_FATAL,      \
        fmt " [%s:%s:%d]\n",     \
        ##__VA_ARGS__,           \
        __FILE__,                \
        __FUNCTION__,            \
        __LINE__)

#define OE_TRACE_ERROR(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_ERROR,      \
        fmt " [%s:%s:%d]\n",     \
        ##__VA_ARGS__,           \
        __FILE__,                \
        __FUNCTION__,            \
        __LINE__)

#define OE_TRACE_WARNING(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_WARNING,      \
        fmt " [%s:%s:%d]\n",       \
        ##__VA_ARGS__,             \
        __FILE__,                  \
        __FUNCTION__,              \
        __LINE__)

#define OE_TRACE_INFO(fmt, ...) \
    OE_TRACE(                   \
        OE_LOG_LEVEL_INFO,      \
        fmt " [%s:%s:%d]\n",    \
        ##__VA_ARGS__,          \
        __FILE__,               \
        __FUNCTION__,           \
        __LINE__)

#define OE_TRACE_VERBOSE(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_VERBOSE,      \
        fmt " [%s:%s:%d]\n",       \
        ##__VA_ARGS__,             \
        __FILE__,                  \
        __FUNCTION__,              \
        __LINE__)

#define OE_RAISE(RESULT, ...)                             \
    do                                                    \
    {                                                     \
        result = (RESULT);                                \
        if (result != OE_OK)                              \
        {                                                 \
            OE_TRACE_ERROR(":%s", oe_result_str(result)); \
        }                                                 \
        goto done;                                        \
    } while (0)

#define OE_RAISE_MSG(RESULT, fmt, ...)                               \
    do                                                               \
    {                                                                \
        result = (RESULT);                                           \
        if (result != OE_OK)                                         \
        {                                                            \
            if (!strcmp(#__VA_ARGS__, "NULL"))                      \
            {                                                        \
                OE_TRACE_ERROR(                                      \
                    fmt " (oe_result_t=%s)", oe_result_str(result)); \
            }                                                        \
            else                                                     \
            {                                                        \
                OE_TRACE_ERROR(                                      \
                    fmt " (oe_result_t=%s)",                         \
                    ##__VA_ARGS__,                                   \
                    oe_result_str(result));                          \
            }                                                        \
        }                                                            \
        goto done;                                                   \
    } while (0)

#define OE_CHECK(EXPRESSION)                 \
    do                                       \
    {                                        \
        oe_result_t _result_ = (EXPRESSION); \
        if (_result_ != OE_OK)               \
            OE_RAISE(_result_);              \
    } while (0)

#define OE_CHECK_MSG(EXPRESSION, fmt, ...)              \
    do                                                  \
    {                                                   \
        oe_result_t _result_ = (EXPRESSION);            \
        if (_result_ != OE_OK)                          \
            OE_RAISE_MSG(_result_, fmt, ##__VA_ARGS__); \
    } while (0)

} // extern "C"
// End of internal OE types and functions

namespace ccf
{

  // Copied from openenclave/common/attest_plugin.c.
  // verify report user data against peer certificate
  static oe_result_t verify_sgx_report_user_data(
      uint8_t* key_buff,
      size_t key_buff_size,
      uint8_t* report_data)
  {
      oe_result_t result = OE_FAILURE;
      oe_sha256_context_t sha256_ctx = {0};
      OE_SHA256 sha256;

      OE_TRACE_VERBOSE(
          "key_buff=[%s] \n oe_strlen(key_buff)=[%d]",
          key_buff,
          strlen((const char*)key_buff));

      // create a hash of public key
      oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
      OE_CHECK(oe_sha256_init(&sha256_ctx));
      OE_CHECK(oe_sha256_update(&sha256_ctx, key_buff, key_buff_size));
      OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

      // validate report's user data against hash(public key)
      if (memcmp(report_data, (uint8_t*)&sha256, OE_SHA256_SIZE) != 0)
      {
          for (int i = 0; i < OE_SHA256_SIZE; i++)
              OE_TRACE_VERBOSE(
                  "[%d] report_data[0x%x] sha256=0x%x ",
                  i,
                  report_data[i],
                  sha256.buf[i]);
          OE_RAISE_MSG(
              OE_VERIFY_FAILED,
              "hash of peer certificate's public key does not match report data",
              NULL);
      }
      result = OE_OK;
  done:
      return result;
  }

  // Copied from openenclave/common/attest_plugin.c.
  // Verify there is a matched claim for the public key
  static oe_result_t _verify_public_key_claim(
      oe_claim_t* claims,
      size_t claims_length,
      uint8_t* public_key_buffer,
      size_t public_key_buffer_size)
  {
      oe_result_t result = OE_FAILURE;
      for (int i = (int)claims_length - 1; i >= 0; i--)
      {
          if (strcmp(claims[i].name, OE_CLAIM_CUSTOM_CLAIMS_BUFFER) == 0)
          {
              if (claims[i].value_size == public_key_buffer_size &&
                  memcmp(
                      claims[i].value,
                      public_key_buffer,
                      public_key_buffer_size) == 0)
              {
                  OE_TRACE_VERBOSE("Found matched public key in claims");
                  result = OE_OK;
                  break;
              }
          }
          if (strcmp(claims[i].name, OE_CLAIM_SGX_REPORT_DATA) == 0)
          {
              if (verify_sgx_report_user_data(
                      public_key_buffer,
                      public_key_buffer_size,
                      claims[i].value) == OE_OK)
              {
                  OE_TRACE_VERBOSE("Found matched public key in claims");
                  result = OE_OK;
                  break;
              }
          }
      }
      return result;
  }

  // Same interface as oe_verify_attestation_certificate_with_evidence.
  oe_result_t verify_maa_root_ca_certificate(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_verify_claims_callback_t claim_verify_callback,
    void* arg)
  {
    oe_result_t result = OE_FAILURE;
    oe_cert_t cert = {0};
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* pub_key_buff = NULL;
    size_t pub_key_buff_size = KEY_BUFF_SIZE;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;
    const size_t maa_header_size = 4;
    uint8_t* sgx_quote;
    sgx_quote_t* quote;
    size_t sgx_quote_size;

    const char* oid_array[] = {oid_maa_sgx_quote_with_collateral};
    size_t oid_array_index = 0;
    size_t oid_array_count = OE_COUNTOF(oid_array);

    pub_key_buff = (uint8_t*)malloc(KEY_BUFF_SIZE);
    if (!pub_key_buff)
      OE_RAISE(OE_OUT_OF_MEMORY);

    result = oe_cert_read_der(&cert, cert_in_der, cert_in_der_len);
    OE_CHECK_MSG(result, "cert_in_der_len=%d", cert_in_der_len);

    // validate the certificate signature
    result = oe_cert_verify(&cert, NULL, NULL, 0);
    OE_CHECK_MSG(
      result, "oe_cert_verify failed with error = %s\n", oe_result_str(result));

    //------------------------------------------------------------------------
    // Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    // set enclave to NULL because we are dealing only with remote report now
    //------------------------------------------------------------------------

    // determine the size of the extension
    while (oid_array_index < oid_array_count)
    {
      if (
        oe_cert_find_extension(
          &cert, (const char*)oid_array[oid_array_index], NULL, &report_size) ==
        OE_BUFFER_TOO_SMALL)
      {
        report = (uint8_t*)malloc(report_size);
        if (!report)
          OE_RAISE(OE_OUT_OF_MEMORY);

        OE_CHECK(oe_cert_find_extension(
          &cert,
          (const char*)oid_array[oid_array_index],
          report,
          &report_size));

        break;
      }

      oid_array_index++;
    }

    // if there is no match
    if (oid_array_index == oid_array_count)
      OE_RAISE(OE_FAILURE);

    // find the extension
    OE_TRACE_VERBOSE("extract_x509_report_extension() succeeded");

    // 'report' contains the whole MAA structure:
    // <2 bytes flags><2 bytes size of quote+collateral><raw SGX quote><collateral>
    // Let's extract the SGX quote from it.
    sgx_quote = report + maa_header_size;
    quote = (sgx_quote_t*)sgx_quote;
    sgx_quote_size = sizeof(sgx_quote_t) + quote->signature_len;
    //size_t collateral_size = report_size - maa_header_size - sgx_quote_size;
    //uint8_t* collateral = sgx_quote + sgx_quote_size;

    result = oe_verify_evidence(
      &_sgx_quote_uuid,
      sgx_quote,
      sgx_quote_size,
      NULL,
      0,
      NULL,
      0,
      &claims,
      &claims_length);

    OE_CHECK(result);
    OE_TRACE_VERBOSE("quote validation succeeded");

    // verify report data: hash(public key)
    // extract public key from the cert
    oe_memset_s(pub_key_buff, KEY_BUFF_SIZE, 0, KEY_BUFF_SIZE);
    result =
      oe_cert_write_public_key_pem(&cert, pub_key_buff, &pub_key_buff_size);
    OE_CHECK(result);
    OE_TRACE_VERBOSE(
      "oe_cert_write_public_key_pem pub_key_buf_size=%d", pub_key_buff_size);

    result = _verify_public_key_claim(
      claims, claims_length, pub_key_buff, pub_key_buff_size);
    OE_CHECK(result);
    OE_TRACE_VERBOSE("user data: hash(public key) validation passed", NULL);

    //---------------------------------------
    // call client to further check claims
    // --------------------------------------
    if (claim_verify_callback)
    {
      result = claim_verify_callback(claims, claims_length, arg);
      OE_CHECK(result);
      OE_TRACE_VERBOSE("claim_verify_callback() succeeded");
    }
    else
    {
      OE_TRACE_WARNING(
        "No claim_verify_callback provided in "
        "oe_verify_attestation_certificate_with_evidence call",
        NULL);
    }

  done:
    free(pub_key_buff);
    oe_free_claims(claims, claims_length);
    oe_cert_free(&cert);
    free(report);
    return result;
  }

}

#pragma GCC diagnostic pop