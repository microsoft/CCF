// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>

// All definitions from the SGX SDK.

#define EXPECT_SIZE(T, S) \
  static_assert(sizeof(T) == S, "unexpected size of " #T);

namespace ravl
{
  namespace sgx
  {
#define SGX_KEYID_SIZE 32
#define SGX_CPUSVN_SIZE 16
#define SGX_CONFIGID_SIZE 64
#define SGX_ISVEXT_PROD_ID_SIZE 16
#define SGX_HASH_SIZE 32
#define SGX_REPORT_DATA_SIZE 64
#define SGX_ISV_FAMILY_ID_SIZE 16
#define SGX_FLAGS_DEBUG 0x0000000000000002ULL

    typedef uint8_t sgx_isvext_prod_id_t[SGX_ISVEXT_PROD_ID_SIZE];
    typedef uint8_t sgx_epid_group_id_t[4];
    typedef uint16_t sgx_isv_svn_t;
    typedef uint32_t sgx_misc_select_t;
    typedef uint8_t sgx_config_id_t[SGX_CONFIGID_SIZE];
    typedef uint16_t sgx_prod_id_t;
    typedef uint8_t sgx_isvfamily_id_t[SGX_ISV_FAMILY_ID_SIZE];
    typedef uint16_t sgx_config_svn_t;

    enum sgx_ql_attestation_algorithm_id_t
    {
      SGX_QL_ALG_EPID = 0,
      SGX_QL_ALG_RESERVED_1 = 1,
      SGX_QL_ALG_ECDSA_P256 = 2,
      SGX_QL_ALG_ECDSA_P384 = 3,
      SGX_QL_ALG_MAX = 4
    };

    enum sgx_ql_cert_key_type_t
    {
      PPID_CLEARTEXT = 1,
      PPID_RSA2048_ENCRYPTED = 2,
      PPID_RSA3072_ENCRYPTED = 3,
      PCK_CLEARTEXT = 4,
      PCK_CERT_CHAIN = 5,
      ECDSA_SIG_AUX_DATA = 6,
      QL_CERT_KEY_TYPE_MAX = 16,
    };

#pragma pack(push, 1)
    struct sgx_basename_t
    {
      uint8_t name[32];
    };
    EXPECT_SIZE(sgx_basename_t, 32);

    struct sgx_cpu_svn_t
    {
      uint8_t svn[SGX_CPUSVN_SIZE];
    };
    EXPECT_SIZE(sgx_cpu_svn_t, SGX_CPUSVN_SIZE);

    struct sgx_attributes_t
    {
      uint64_t flags;
      uint64_t xfrm;
    };
    EXPECT_SIZE(sgx_attributes_t, 16);

    struct sgx_measurement_t
    {
      uint8_t m[SGX_HASH_SIZE];
    };
    EXPECT_SIZE(sgx_measurement_t, SGX_HASH_SIZE);

    struct sgx_report_data_t
    {
      uint8_t d[SGX_REPORT_DATA_SIZE];
    };
    EXPECT_SIZE(sgx_report_data_t, SGX_REPORT_DATA_SIZE);

    struct sgx_report_body_t
    {
      sgx_cpu_svn_t cpu_svn;
      sgx_misc_select_t misc_select;
      uint8_t reserved1[12];
      sgx_isvext_prod_id_t isv_ext_prod_id;
      sgx_attributes_t attributes;
      sgx_measurement_t mr_enclave;
      uint8_t reserved2[32];
      sgx_measurement_t mr_signer;
      uint8_t reserved3[32];
      sgx_config_id_t config_id;
      sgx_prod_id_t isv_prod_id;
      sgx_isv_svn_t isv_svn;
      sgx_config_svn_t config_svn;
      uint8_t reserved4[42];
      sgx_isvfamily_id_t isv_family_id;
      sgx_report_data_t report_data;
    };
    EXPECT_SIZE(sgx_report_body_t, 384);

    struct sgx_quote_t
    {
      uint16_t version;
      uint16_t sign_type;
      sgx_epid_group_id_t epid_group_id;
      sgx_isv_svn_t qe_svn;
      sgx_isv_svn_t pce_svn;
      uint32_t xeid;
      sgx_basename_t basename;
      sgx_report_body_t report_body;
      uint32_t signature_len;
      uint8_t signature[];
    };
    EXPECT_SIZE(sgx_quote_t, 436);

    struct sgx_ql_auth_data_t
    {
      uint16_t size;
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable : 4200)
#endif
      uint8_t auth_data[];
#ifdef _MSC_VER
#  pragma warning(pop)
#endif
    };
    EXPECT_SIZE(sgx_ql_auth_data_t, 2);

    struct sgx_ql_certification_data_t
    {
      uint16_t cert_key_type;
      uint32_t size;
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable : 4200)
#endif
      uint8_t certification_data[];
#ifdef _MSC_VER
#  pragma warning(pop)
#endif
    };
    EXPECT_SIZE(sgx_ql_certification_data_t, 6);

    struct sgx_ql_ecdsa_sig_data_t
    {
      uint8_t sig[32 * 2];
      uint8_t attest_pub_key[32 * 2];
      sgx_report_body_t qe_report;
      uint8_t qe_report_sig[32 * 2];
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable : 4200)
#else
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wpedantic"
#endif
      uint8_t auth_certification_data[];
#ifdef _MSC_VER
#  pragma warning(pop)
#else
#  pragma GCC diagnostic pop
#endif
    };
    EXPECT_SIZE(sgx_ql_ecdsa_sig_data_t, 576);

#pragma pack(pop)
  }
}
